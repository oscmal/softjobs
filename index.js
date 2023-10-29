const jwt = require ("jsonwebtoken");
const express = require ("express");
const app = express ();
const cors = require ("cors");
const bcrypt = require ("bcryptjs");
// require ("dotenv").config();
const { obtenerUsuarioPorEmail, registrarUsuario} = require ("./consultas");

const PORT = 3000;
app.listen(PORT, console.log("SERVER ON", PORT));
app.use(cors());
app.use(express.json());

// middlewares
const verificarCredenciales = (req, res, next) => {
    const { email, password, rol, lenguage } = req.body;
    if (!email || !password || !rol || !lenguage) {
      return res.status(401).json({ message: "Faltan credenciales" });
    }
    next();
  };
  
  const verificarCredencialesLogin = (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(401).json({ message: "Faltan credenciales" });
    }
    next();
  };

  const validarToken = (req, res, next) => {
    const Authorization = req.header("Authorization");
    const token = Authorization.split("Bearer ")[1];
    if (!token) {
      return res.status(401).json({ message: "No se proporcionó un token" });
    }
    jwt.verify(token, "llaveSecreta", (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Token inválido" });
      }
      req.email = decoded;
      next();
    });
  };
  
  const reportarConsultas = (req, res, next) => {
    console.log("Consulta recibida:", req.method, req.url);
    next();
  };
  
  // Rutas
  app.post("/usuarios", verificarCredenciales, async (req, res) => {
    try {
      const usuario = req.body;
      await registrarUsuario(usuario);
      res.send("Usuario creado con éxito");
    } catch (error) {
      res.status(500).send(error);
    }
  });
  
  app.post("/login", verificarCredencialesLogin, async (req, res) => {
    const { email, password } = req.body;
    const usuario = await obtenerUsuarioPorEmail(email);
    if (!usuario) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }
    const passwordCorrecta = await bcrypt.compare(password, usuario.password);
    if (!passwordCorrecta) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }
    const token = jwt.sign({ email: usuario.email }, "llaveSecreta");
    res.send(token);
  });
  
  app.get("/usuarios", validarToken, async (req, res) => {
    const { email } = req.email;
    const usuario = await obtenerUsuarioPorEmail(email);
    if (!usuario) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    const usuarioSinClave = { email: usuario.email, rol: usuario.rol, lenguage: usuario.lenguage }
    res.json(usuarioSinClave);
  });
  
  app.use(reportarConsultas);
  
  // Manejo de errores
  app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Error en el servidor" });
  });