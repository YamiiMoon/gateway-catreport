// Projeto Ironclad AG-7742-X - Gateway Segura para Evelyn Reed
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const cors = require('cors');

const app = express();

app.set('trust proxy', 1);
// ========== MERCADO PAGO ==========
const { MPFacil } = require('mp-facil');
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION');
  console.error(err);
});

process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION');
  console.error(err);
});

const mp = new MPFacil({
  apiKey: 'APP_USR-5273242514038984-070905-75205609422dbf60161e0d9242565391-3197875267',  // Cole o token que você copiou
  webhookUrl: 'https://gateway-catreport-production.up.railway.app'  // URL do Railway + /webhook-pagamento
});
const PORT = process.env.PORT || 3000;

// ========== CHAVES E CRIPTOGRAFIA ==========
const SECRET_KEY = crypto.randomBytes(32).toString('hex');
const AES_KEY = crypto.randomBytes(32);

// ========== LOGGER ==========
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.File({ filename: 'ironclad-gateway.log' })]
});

// ========== MIDDLEWARES ==========
app.use(cors()); // Permite requisições de qualquer origem
app.use(helmet());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100,
  message: { error: "Taxa excedida - Acesso monitorado pelo Ironclad" }
});
app.use(limiter);

// ========== ROTA PRINCIPAL ==========
app.get('/', (req, res) => {
  res.send('🚀 Servidor Ironclad rodando! Acesse /login ou /process');
});

// ========== AUTENTICAÇÃO JWT ==========
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Acesso negado - Ironclad Protocol" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
};

// ========== CRIPTOGRAFIA AES-256 ==========
function encrypt(data) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return { iv: iv.toString('hex'), encrypted: encrypted.toString('hex') };
}

// ========== ROTA DE LOGIN ==========
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync('senhaSeguraOmega', 10);
  if (username === 'evelyn.reed' && bcrypt.compareSync(password, hashedPassword)) {
    const token = jwt.sign({ user: username, clearance: 'Omega' }, SECRET_KEY, { expiresIn: '1h' });
    logger.info({ action: 'login_success', user: username, timestamp: new Date().toISOString() });
    res.json({ token });
  } else {
    res.status(401).json({ error: "Credenciais inválidas" });
  }
});

// ========== ROTA PROTEGIDA (PROCESS) ==========
app.post('/process', authenticateToken, (req, res) => {
  const payload = req.body;
  const encrypted = encrypt(payload);
  logger.info({ 
    action: 'process_request', 
    user: req.user.user, 
    payloadHash: crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex') 
  });

  res.json({ 
    status: "success", 
    message: "Requisição processada via Ironclad Gateway", 
    encryptedData: encrypted 
  });
});
// ========== ROTA PARA CRIAR PAGAMENTO PIX ==========
app.post('/criar-pagamento', async (req, res) => {
  const { valor, produto, emailPagador } = req.body;

  try {
    // 1. CRIA O PIX
    const cobranca = await mp.criarPix({
      produto: produto,
      id: `pedido-${Date.now()}`,
      preco: valor,
      emailPagador: emailPagador || "cliente@email.com"
    });

    if (!cobranca.ok) {
      return res.status(500).json({ erro: cobranca.mensagem });
    }

    // 2. CONSULTA O PAGAMENTO PARA PEGAR O QR CODE
    const pagamentoId = cobranca.dados.id;
    const consulta = await mp.consultarCobranca(pagamentoId);

    if (!consulta.ok) {
      return res.status(500).json({ erro: consulta.mensagem });
    }

    // 3. RETORNA OS DADOS COMPLETOS PARA O SITE
    res.json({
      qrCode: consulta.dados.qrCodeBase64,
      copiaCola: consulta.dados.copiaECola
    });

  } catch (error) {
    console.error("ERRO AO CRIAR PIX:", error);
    res.status(500).json({ erro: error.message });
  }
});

// ========== INICIALIZAÇÃO DO SERVIDOR ==========
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Gateway rodando na porta ${PORT}`);

  logger.info({ status: 'gateway_started', port: PORT });
});