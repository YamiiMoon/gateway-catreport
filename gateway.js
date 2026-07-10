// ========== GATEWAY CATreport - PRODUÇÃO FINAL (10/10) ==========
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');
const crypto = require('crypto');
const morgan = require('morgan');
const { Pool } = require('pg');
const winston = require('winston');
const { Resend } = require('resend');
const OpenAI = require('openai');

const app = express();
const PORT = process.env.PORT || 3000;

// ========== CONFIGURAÇÕES ==========
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',')
  : ['http://localhost:5500', 'http://127.0.0.1:5500'];

const ASAAS_API_KEY = process.env.ASAAS_API_KEY;
const ASAAS_WEBHOOK_TOKEN = process.env.ASAAS_WEBHOOK_TOKEN;
const DATABASE_URL = process.env.DATABASE_URL;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

// ========== INICIALIZAÇÃO DO RESEND ==========
const resend = new Resend(process.env.RESEND_API_KEY);
const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY
});

// ========== VALIDAÇÕES INICIAIS ==========
if (!ASAAS_API_KEY) {
  console.error('❌ ASAAS_API_KEY não configurada no Railway!');
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL não configurada no Railway!');
  process.exit(1);
}

if (!ENCRYPTION_KEY) {
  console.error('❌ ENCRYPTION_KEY não configurada no Railway!');
  console.error('💡 Gere uma chave com: node -e "console.log(crypto.randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// ========== VALIDAÇÃO DA CHAVE AES ==========
const KEY = Buffer.from(ENCRYPTION_KEY, 'hex');
if (KEY.length !== 32) {
  console.error('❌ ENCRYPTION_KEY inválida. Deve ter exatamente 32 bytes (64 caracteres hex)');
  console.error('💡 Gere uma chave com: node -e "console.log(crypto.randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}
console.log('✅ ENCRYPTION_KEY validada com sucesso');

// ========== LOGGER ==========
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// ========== BANCO DE DADOS ==========
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000 // Aumentado de 2000 para 5000
});

pool.on('error', (err) => {
  logger.error('❌ Erro inesperado no PostgreSQL:', err);
});

// ========== FUNÇÕES DE ENCRIPTAÇÃO ==========
function encrypt(text) {
  if (!text) return null;
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (err) {
    logger.error('❌ Erro ao criptografar:', err);
    return null;
  }
}

function decrypt(encryptedText) {
  if (!encryptedText) return null;
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) return null;
    
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    logger.error('❌ Erro ao descriptografar:', err);
    return null;
  }
}

// ========== FUNÇÕES DE UTILITÁRIO ==========
function ofuscarCPF(cpf) {
  if (!cpf) return '***';
  const limpo = cpf.replace(/\D/g, '');
  if (limpo.length !== 11) return '***';
  return `${limpo.substring(0, 3)}******${limpo.substring(9)}`;
}

function ofuscarEmail(email) {
  if (!email) return '***';
  const [local, dominio] = email.split('@');
  if (!dominio) return email;
  return `${local.substring(0, 2)}****@${dominio}`;
}

function sanitizarString(texto, maxLength = 255) {
  if (!texto) return '';
  return texto.trim().substring(0, maxLength);
}

function validarCPF(cpf) {
  const cpfLimpo = cpf.replace(/\D/g, '');
  
  if (cpfLimpo.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(cpfLimpo)) return false;
  
  const validarDigito = (base, multiplicador) => {
    let soma = 0;
    for (let i = 0; i < base.length; i++) {
      soma += parseInt(base[i]) * multiplicador--;
    }
    const resto = soma % 11;
    const digito = resto < 2 ? 0 : 11 - resto;
    return digito === parseInt(cpfLimpo[base.length]);
  };

  return validarDigito(cpfLimpo.substring(0, 9), 10) &&
         validarDigito(cpfLimpo.substring(0, 10), 11);
}

function validarEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

function validarValor(valor) {
  const valorNumerico = Number(valor);
  return Number.isFinite(valorNumerico) && valorNumerico > 0;
}

// ========== RETRY ==========
async function fetchWithRetry(url, options = {}, timeout = 15000, maxRetries = 3) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      
      const response = await fetch(url, {
        ...options,
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      return response;
      
    } catch (error) {
      lastError = error;
      logger.warn(`🔄 Tentativa ${attempt}/${maxRetries} falhou: ${error.message}`);
      
      if (attempt < maxRetries) {
        const delay = attempt * 500;
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw new Error(`Falha após ${maxRetries} tentativas: ${lastError.message}`);
}

// ========== MIDDLEWARES ==========
app.use(helmet());

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (CORS_ORIGINS.includes(origin)) {
      return callback(null, true);
    } else {
      logger.warn(`⚠️ CORS bloqueado para origem: ${origin}`);
      return callback(new Error('Origem não permitida pelo CORS'));
    }
  }
}));

app.use(express.json({ limit: '1mb' }));
app.use(morgan('combined'));

// ========== RATE LIMIT APENAS NA ROTA DE CRIAÇÃO ==========
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Muitas requisições. Tente novamente mais tarde." }
});

// ========== INICIALIZAÇÃO DO BANCO ==========
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS pedidos (
        id TEXT PRIMARY KEY,
        external_reference TEXT UNIQUE,
        customer_id TEXT NOT NULL,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        cpf TEXT NOT NULL,
        desafio TEXT,
        valor NUMERIC(10,2) NOT NULL,
        produto VARCHAR(120) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
        email_sent BOOLEAN NOT NULL DEFAULT FALSE,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT status_check CHECK (
          status IN ('PENDING', 'PAID', 'CANCELLED', 'REFUNDED', 'EXPIRED')
        )
      )
    `);

    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_pedidos_status ON pedidos(status);
      CREATE INDEX IF NOT EXISTS idx_pedidos_criado_em ON pedidos(criado_em);
    `);

    logger.info('✅ Banco de dados PostgreSQL inicializado');
  } catch (err) {
    logger.error('❌ Erro ao inicializar banco:', err);
    process.exit(1);
  }
}

// ========== FUNÇÕES DO BANCO ==========
async function salvarPedido(pedidoId, dados) {
  const emailCriptografado = encrypt(dados.email);
  const cpfCriptografado = encrypt(dados.cpf);

  const query = `
    INSERT INTO pedidos (
      id, external_reference, customer_id, nome, email, cpf, desafio,
      valor, produto, status, criado_em, atualizado_em
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (id) DO UPDATE SET
      external_reference = EXCLUDED.external_reference,
      customer_id = EXCLUDED.customer_id,
      nome = EXCLUDED.nome,
      email = EXCLUDED.email,
      cpf = EXCLUDED.cpf,
      desafio = EXCLUDED.desafio,
      valor = EXCLUDED.valor,
      produto = EXCLUDED.produto,
      status = EXCLUDED.status,
      atualizado_em = CURRENT_TIMESTAMP
  `;

  await pool.query(query, [
    pedidoId,
    dados.externalReference,
    dados.customerId,
    dados.nome,
    emailCriptografado,
    cpfCriptografado,
    dados.desafio || '',
    dados.valor,
    dados.produto,
    dados.status || 'PENDING',
    dados.criadoEm || new Date().toISOString(),
    new Date().toISOString()
  ]);

  logger.info(`📝 Pedido ${pedidoId} salvo com sucesso!`);
}

async function buscarPedidoPorId(pedidoId) {
  const result = await pool.query('SELECT * FROM pedidos WHERE id = $1', [pedidoId]);
  const pedido = result.rows[0];
  if (pedido) {
    pedido.email = decrypt(pedido.email);
    pedido.cpf = decrypt(pedido.cpf);
  }
  return pedido || null;
}

async function buscarPedidoPorReferencia(externalReference) {
  const result = await pool.query('SELECT * FROM pedidos WHERE external_reference = $1', [externalReference]);
  const pedido = result.rows[0];
  if (pedido) {
    pedido.email = decrypt(pedido.email);
    pedido.cpf = decrypt(pedido.cpf);
  }
  return pedido || null;
}

async function atualizarStatusPedido(pedidoId, status) {
  const result = await pool.query(
    'UPDATE pedidos SET status = $1, atualizado_em = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
    [status, pedidoId]
  );
  
  if (result.rowCount > 0) {
    logger.info(`✅ Pedido ${pedidoId} atualizado para: ${status}`);
    const pedido = result.rows[0];
    pedido.email = decrypt(pedido.email);
    pedido.cpf = decrypt(pedido.cpf);
    return pedido;
  }
  
  logger.warn(`⚠️ Pedido ${pedidoId} não encontrado`);
  return null;
}

async function marcarEmailEnviado(pedidoId) {
  await pool.query(
    'UPDATE pedidos SET email_sent = TRUE WHERE id = $1',
    [pedidoId]
  );
  logger.info(`📧 Email marcado como enviado para pedido ${pedidoId}`);
}

// ========== HEALTH CHECK ==========
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as agora');
    res.json({ 
      status: 'ok', 
      timestamp: result.rows[0].agora,
      banco: 'conectado'
    });
  } catch (err) {
    logger.error('❌ Health check falhou:', err);
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ========== ROTA PRINCIPAL ==========
app.get('/', (req, res) => {
  res.send('🚀 Gateway CATreport rodando!');
});

// ========== ROTA DE CONSULTA ==========
app.get('/pagamento/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const pedido = await buscarPedidoPorId(id) || await buscarPedidoPorReferencia(id);
    
    if (!pedido) {
      return res.status(404).json({ error: 'Pedido não encontrado' });
    }
    
    res.json({
      id: pedido.id,
      status: pedido.status,
      valor: pedido.valor,
      produto: pedido.produto,
      criado_em: pedido.criado_em,
      atualizado_em: pedido.atualizado_em
    });
  } catch (error) {
    logger.error('❌ Erro ao consultar pedido:', error);
    res.status(500).json({ error: error.message });
  }
});

// ========== FUNÇÃO PARA BUSCAR OU CRIAR CLIENTE ==========
async function buscarOuCriarCliente(nome, email, cpf) {
  const cpfLimpo = cpf.replace(/\D/g, '');
  
  logger.info(`🔍 Buscando cliente por CPF: ${ofuscarCPF(cpfLimpo)}`);
  const buscaResponse = await fetchWithRetry(
    `https://api.asaas.com/v3/customers?cpfCnpj=${cpfLimpo}`,
    { headers: { 'access_token': ASAAS_API_KEY } }
  );

  if (!buscaResponse.ok) {
    throw new Error(`Erro ao consultar clientes (CPF): ${buscaResponse.status}`);
  }

  const buscaData = await buscaResponse.json();

  if (buscaData.data && buscaData.data.length > 0) {
    logger.info(`✅ Cliente encontrado por CPF: ${buscaData.data[0].id}`);
    return buscaData.data[0].id;
  }

  logger.info(`🔍 Buscando cliente por e-mail: ${ofuscarEmail(email)}`);
  const buscaEmailResponse = await fetchWithRetry(
    `https://api.asaas.com/v3/customers?email=${encodeURIComponent(email)}`,
    { headers: { 'access_token': ASAAS_API_KEY } }
  );

  if (!buscaEmailResponse.ok) {
    throw new Error(`Erro ao consultar clientes (e-mail): ${buscaEmailResponse.status}`);
  }

  const buscaEmailData = await buscaEmailResponse.json();

  if (buscaEmailData.data && buscaEmailData.data.length > 0) {
    logger.info(`✅ Cliente encontrado por e-mail: ${buscaEmailData.data[0].id}`);
    return buscaEmailData.data[0].id;
  }

  logger.info('📝 Criando novo cliente...');
  const criaResponse = await fetchWithRetry(
    'https://api.asaas.com/v3/customers',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'access_token': ASAAS_API_KEY
      },
      body: JSON.stringify({
        name: sanitizarString(nome, 120),
        email: email,
        cpfCnpj: cpfLimpo,
        notificationDisabled: true
      })
    }
  );

  if (!criaResponse.ok) {
    const errorData = await criaResponse.json();
    throw new Error(errorData.errors?.[0]?.description || `Erro ao criar cliente: ${criaResponse.status}`);
  }

  const criaData = await criaResponse.json();

  if (!criaData.id) {
    throw new Error('Cliente criado mas sem ID retornado');
  }

  logger.info(`✅ Cliente criado: ${criaData.id}`);
  return criaData.id;
}

// ========== ROTA PARA CRIAR PAGAMENTO PIX ==========
app.post('/criar-pagamento', limiter, async (req, res) => {
  try {
    let { valor, produto, nome, emailPagador, cpf, desafio } = req.body;

    nome = sanitizarString(nome, 120);
    produto = sanitizarString(produto, 120);
    desafio = sanitizarString(desafio, 500);
    emailPagador = emailPagador?.trim() || '';
    cpf = cpf?.replace(/\D/g, '') || '';

    if (!valor || !produto || !nome || !emailPagador || !cpf) {
      return res.status(400).json({
        erro: 'Todos os campos são obrigatórios: valor, produto, nome, emailPagador, cpf'
      });
    }

    if (!validarValor(valor)) {
      return res.status(400).json({
        erro: 'Valor deve ser um número maior que zero'
      });
    }

    if (!validarCPF(cpf)) {
      return res.status(400).json({
        erro: 'CPF inválido'
      });
    }

    if (!validarEmail(emailPagador)) {
      return res.status(400).json({
        erro: 'E-mail inválido'
      });
    }

    const customerId = await buscarOuCriarCliente(nome, emailPagador, cpf);

    const externalReference = crypto.randomUUID();
    logger.info(`📝 Criando cobrança para cliente: ${customerId}`);

    const cobrancaResponse = await fetchWithRetry(
      'https://api.asaas.com/v3/payments',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'access_token': ASAAS_API_KEY
        },
        body: JSON.stringify({
          customer: customerId,
          billingType: 'PIX',
          value: Number(valor),
          dueDate: new Date().toISOString().split('T')[0],
          description: produto,
          externalReference: externalReference
        })
      }
    );

    if (!cobrancaResponse.ok) {
      const errorData = await cobrancaResponse.json();
      throw new Error(errorData.errors?.[0]?.description || `Erro ao criar cobrança: ${cobrancaResponse.status}`);
    }

    const dadosCobranca = await cobrancaResponse.json();

    if (!dadosCobranca.id) {
      throw new Error('Cobrança criada mas sem ID retornado');
    }

    logger.info(`✅ Cobrança criada: ${dadosCobranca.id}`);

    await salvarPedido(dadosCobranca.id, {
      externalReference,
      customerId,
      nome,
      email: emailPagador,
      cpf,
      desafio: desafio || '',
      valor: Number(valor),
      produto,
      status: 'PENDING',
      criadoEm: new Date().toISOString()
    });

    logger.info('📝 Buscando QR Code...');
    const qrResponse = await fetchWithRetry(
      `https://api.asaas.com/v3/payments/${dadosCobranca.id}/pixQrCode`,
      { headers: { 'access_token': ASAAS_API_KEY } }
    );

    if (!qrResponse.ok) {
      throw new Error(`Erro ao buscar QR Code: ${qrResponse.status}`);
    }

    const qrData = await qrResponse.json();

    if (!qrData.payload) {
      throw new Error('QR Code não retornado pelo Asaas');
    }

    const codigoPix = qrData.payload;

    let qrCodeImage = null;
    try {
      qrCodeImage = await QRCode.toDataURL(codigoPix);
      logger.info('✅ QR Code gerado com sucesso!');
    } catch (err) {
      logger.error('❌ Erro ao gerar imagem do QR Code:', err);
    }

    res.json({
      qrCode: qrCodeImage,
      copiaCola: codigoPix,
      id: dadosCobranca.id,
      customerId: customerId
    });

  } catch (error) {
    logger.error('❌ ERRO:', error.message);
    res.status(500).json({ erro: error.message });
  }
});

// ========== FUNÇÃO PARA GERAR RELATÓRIO COM IA (VERSÃO REFINADA) ==========
async function gerarRelatorio(nome, desafio, email) {
  try {
    const prompt = `
Você é o Dr. Marcus Vale, consultor de negócios com 15 anos de experiência ajudando PMEs brasileiras a crescerem de forma sustentável.
Sou direto, prático e não perco tempo com teorias. Se não for para resolver o problema de verdade, não vou sugerir.

Cliente: ${nome}
E-mail: ${email}
Desafio principal: ${desafio}

**Instruções rigorosas:**
- NÃO use frases genéricas como "é importante" sem explicar o porquê prático.
- NÃO dê conselhos óbvios sem detalhar o "como fazer".
- Seja extremamente objetivo, use linguagem brasileira direta.
- Prefira frases curtas e listas.
- Pense passo a passo antes de responder.

**Estrutura obrigatória do relatório:**
1. **Resumo Executivo** (máximo 4 frases impactantes)
2. **Análise do Problema** (exatamente 3 causas raiz mais prováveis)
3. **Oportunidades de Melhoria** (exatamente 5, priorizadas, com nível de impacto e facilidade de execução)
4. **Ferramentas Recomendadas** (separe em Gratuitas e Pagas, com link quando possível e justificativa curta)
5. **Plano de Ação** (detalhado para 30, 60 e 90 dias, com responsáveis sugeridos e métricas claras de sucesso)

**Exemplo de formato:**
1. **Resumo Executivo**  
   - Frase 1...  
   - Frase 2...

Agora gere o relatório completo para este cliente. Seja prático, acionável e vá direto ao ponto.
`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.62,
      max_tokens: 2500,
      presence_penalty: 0.15,
      frequency_penalty: 0.15
    });

    const relatorio = response.choices[0].message.content;
    logger.info(`✅ Relatório gerado para ${email}`);
    return relatorio;
  } catch (error) {
    logger.error('❌ Erro ao gerar relatório:', error);
    throw error;
  }
}

// ========== FUNÇÃO PARA ENVIAR RELATÓRIO POR E-MAIL ==========
async function enviarRelatorioPorEmail(email, nome, relatorio) {
  try {
    const { data, error } = await resend.emails.send({
      from: 'CATreport <naoresponda@catreport.com>', // Substitua pelo seu domínio
      to: [email],
      subject: `📊 Seu relatório personalizado - CATreport`,
      html: `
        <h2>Olá, ${nome}!</h2>
        <p>Seu relatório personalizado foi gerado com sucesso. Confira abaixo:</p>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; white-space: pre-wrap;">
          ${relatorio.replace(/\n/g, '<br>')}
        </div>
        <p style="margin-top: 20px; color: #666;">
          Atenciosamente,<br/>
          <strong>Equipe CATreport</strong>
        </p>
      `
    });

    if (error) {
      logger.error('❌ Erro ao enviar e-mail:', error);
      throw error;
    }

    logger.info(`✅ E-mail enviado para ${email}`);
    return data;
  } catch (error) {
    logger.error('❌ Erro ao enviar e-mail:', error);
    throw error;
  }
}

// ========== WEBHOOK DO ASAAS ==========
let webhookLogado = false;

app.post('/webhook', async (req, res) => {
  try {
    const event = req.body;
    logger.info('📩 Webhook recebido');

    // ===== LOG DOS HEADERS APENAS UMA VEZ =====
    if (!webhookLogado) {
      logger.info('📝 HEADERS DO WEBHOOK:');
      logger.info(JSON.stringify(req.headers, null, 2));
      logger.info('📝 FORMATO COMPLETO DO WEBHOOK:');
      logger.info(JSON.stringify(event, null, 2));
      webhookLogado = true;
    }

    logger.info(`📌 Evento: ${event.event}`);
    logger.info(`📌 ID: ${event.payment?.id || event.data?.id}`);

    // ===== VALIDAÇÃO DO TOKEN (SOMENTE O HEADER CORRETO) =====
    // APÓS VERIFICAR O LOG, SUBSTITUA PELO HEADER CORRETO
    // Exemplo: const token = req.headers['asaas-webhook-token'];
    // Deixe apenas UM dos abaixo:
    const token = req.headers['asaas-webhook-token'] || 
                  req.headers['x-asaas-webhook-token'] ||
                  req.headers['asaas-access-token'] ||
                  req.headers['x-asaas-access-token'];
    
    if (ASAAS_WEBHOOK_TOKEN) {
      if (token !== ASAAS_WEBHOOK_TOKEN) {
        logger.warn('⚠️ Token inválido!');
        return res.status(401).json({ error: 'Token inválido' });
      }
      logger.info('✅ Token validado com sucesso');
    }

    // ===== PROCESSA O EVENTO =====
    if (event.event === 'PAYMENT_CONFIRMED' || event.event === 'PAYMENT_RECEIVED') {
      const paymentId = event.payment?.id || event.data?.id;
      const externalReference = event.payment?.externalReference || event.data?.externalReference;

      let pedido = null;
      if (externalReference) {
        pedido = await buscarPedidoPorReferencia(externalReference);
      }
      if (!pedido && paymentId) {
        pedido = await buscarPedidoPorId(paymentId);
      }

      if (!pedido) {
        logger.warn(`⚠️ Pedido não encontrado: ${paymentId || externalReference}`);
        return res.status(404).json({ error: 'Pedido não encontrado' });
      }

      if (pedido.status === 'PAID' || pedido.status === 'CONFIRMED') {
        logger.info(`ℹ️ Pedido ${paymentId} já processado. Ignorando.`);
        return res.sendStatus(200);
      }

      logger.info(`✅ Pagamento confirmado! ID: ${paymentId}`);
      const pedidoAtualizado = await atualizarStatusPedido(pedido.id, 'PAID');

      if (pedidoAtualizado && !pedido.email_sent) {
  logger.info(`📧 Gerando relatório para ${pedido.email}...`);

  // ===== GERA O RELATÓRIO COM IA =====
  const relatorio = await gerarRelatorio(
    pedido.nome,
    pedido.desafio || 'Nenhum desafio informado',
    pedido.email
  );

  // ===== ENVIA O RELATÓRIO POR E-MAIL =====
  await enviarRelatorioPorEmail(pedido.email, pedido.nome, relatorio);

  // ===== MARCA COMO ENVIADO =====
  await marcarEmailEnviado(pedido.id);
}
    } else {
      logger.info(`ℹ️ Evento ignorado: ${event.event}`);
    }

    // ===== RESPONDE 200 APÓS PROCESSAR =====
    res.sendStatus(200);

  } catch (error) {
    logger.error('❌ Erro no webhook:', error.message);
    // Retorna 500 para o Asaas reenviar
    res.status(500).json({ error: error.message });
  }
});

// ========== INICIALIZAÇÃO ==========
async function start() {
  await initDatabase();

  app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 Gateway rodando na porta ${PORT}`);
    logger.info(`📡 Webhook: https://gateway-catreport-production.up.railway.app/webhook`);
    logger.info(`🔑 Asaas: ${ASAAS_API_KEY ? '✅' : '❌'}`);
    logger.info(`🔐 Webhook Token: ${ASAAS_WEBHOOK_TOKEN ? '✅' : '⚠️'}`);
    logger.info(`🔑 Encryption Key: ${ENCRYPTION_KEY ? '✅' : '❌'}`);
    logger.info(`💾 Banco: PostgreSQL (persistente)`);
    logger.info(`📊 Health: https://gateway-catreport-production.up.railway.app/health`);
    logger.info(`📋 Rotas de consulta: GET /pagamento/:id`);
  });

  const gracefulShutdown = async (signal) => {
    logger.info(`🛑 Recebido ${signal}. Encerrando...`);
    await pool.end();
    logger.info('✅ Conexões com banco encerradas');
    process.exit(0);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

start();