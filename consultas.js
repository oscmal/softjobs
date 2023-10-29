const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  host:"localhost",
  user: "postgres",
  password: "postgres",
  database: "softjobs",
  allowExitOnIdle: true,
});

const registrarUsuario = async (usuario) => {
  const { email, password, rol, lenguage } = usuario;
  const passwordEncriptada = bcrypt.hashSync(password, 10);
  const consulta =
    "INSERT INTO usuarios (email, password, rol, lenguage) values($1, $2, $3, $4)";
  const values = [email, passwordEncriptada, rol, lenguage];
  const result = await pool.query(consulta, values);
};

const obtenerUsuarioPorEmail = async (email) => {
  const consulta = "SELECT * FROM usuarios WHERE email = $1";
  const value = [email]
  const { rows } = await pool.query(consulta, value);
  return rows[0];
};

module.exports = {
  registrarUsuario,
  obtenerUsuarioPorEmail,
};