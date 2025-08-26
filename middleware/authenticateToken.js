// middleware/authenticateToken.js
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Extrae token después de "Bearer"

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('Token inválido:', err.message);
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }

    req.user = user; // Asigna el payload decodificado al request
    next();
  });
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    const userRole = req.user.rolId;

    if (!allowedRoles.includes(userRole)) {
      return res.status(403).json({ error: 'No tienes permiso para acceder a este recurso' });
    }

    next();
  };
}

module.exports = {
  authenticateToken,
  authorizeRoles
};

