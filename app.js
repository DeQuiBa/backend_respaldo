  // server.js
  const express = require('express');
  const { Pool } = require('pg');
  const cors = require('cors');
  const dotenv = require('dotenv');
  const jwt = require('jsonwebtoken');
  const { authenticateToken, authorizeRoles} = require('./middleware/authenticateToken');
  const { enviarCorreo } = require("./email/emailService");
  const crypto = require('crypto');
  const bcrypt = require('bcrypt');
  
  const { router_monto } = require('./routes/monto.routes');
  const { router_comite } = require('./routes/comite.routes');
  const { router_roles } = require('./routes/roles.routes');
  const { swaggerUi, swaggerSpec } = require('./config/swagger');
  const FileType = require("file-type");

const multer = require("multer");
const upload = multer(); // usa memoria, no guarda archivos en disco

  dotenv.config();

  //s Configuración de Express
  const app = express();
  app.use(express.json());

  // ver la documentacion de APIS
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));


  // CORS
  const corsOptions = {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  };
  app.use(cors(corsOptions));

  // Conexión a PostgreSQL
  const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
  });

  // Endpoint de prueba
  app.get('/', async (req, res) => {
    try {
      const result = await pool.query('SELECT NOW()');
      res.json({ message: 'Servidor funcionando', dbTime: result.rows[0].now });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error conectando a la base de datos' });
    }
  });

  // Puerto del servidor
  const PORT = process.env.PORT || 3050;
  app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Docs Swagger en http://localhost:${PORT}/api-docs`);
  });


   // ===================================================
  // Envio de la contraseña
  // ===================================================

  app.post('/api/auth/forgot-password', async (req, res) => {
    try {
      const { correo } = req.body;

      if (!correo) return res.status(400).json({ error: 'Correo requerido' });

      // Buscar usuario
      const result = await pool.query('SELECT id, correo FROM usuarios WHERE correo = $1', [correo]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const user = result.rows[0];

      // Generar token
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

      // Guardar token en la tabla
      await pool.query(
        `INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)`,
        [user.id, token, expiresAt]
      );

      // Link de recuperación
      const resetLink = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;

      // Enviar correo con diseño mejorado
      const html = `
        <div style="font-family: Arial, sans-serif; background-color: #f0f2f5; padding: 40px; text-align: center;">
          <div style="background-color: #ffffff; max-width: 500px; margin: auto; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
            <h1 style="color: #1d4ed8; margin-bottom: 8px; font-size: 28px; text-align: center;">
              SISGEFI-DK
            </h1>
            <h2 style="color: #333; margin-bottom: 20px; font-size: 20px; text-align: center;">
              Sistema de Gestión Financiera – Ingresos y Egresos
            </h2>
            <p style="color: #555; font-size: 16px; margin-bottom: 25px; text-align: center;">
              Para restablecer tu contraseña, haz clic en el siguiente botón:
            </p>
            <a href="${resetLink}" target="_blank"
              style="display: inline-block; padding: 12px 25px; background-color: #1d4ed8;
                    color: #fff; font-size: 16px; font-weight: bold; text-decoration: none;
                    border-radius: 8px; box-shadow: 0 3px 6px rgba(0,0,0,0.15); transition: background-color 0.3s;">
              Restablecer Contraseña
            </a>
            <p style="margin-top: 25px; color: #888; font-size: 14px; text-align: center;">
              Este enlace expirará en 5 minutos.
            </p>
          </div>
        </div>
      `;

      await enviarCorreo(user.correo, 'Recuperación de contraseña - SISGEFI-DK', html);

      res.json({ message: 'Correo de recuperación enviado' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error en el servidor' });
    }
  });


  app.post('/api/auth/reset-password', async (req, res) => {
      try {
        const { token, password } = req.body;

        if (!token || !password) return res.status(400).json({ error: 'Datos incompletos' });

        // Buscar el token
        const tokenResult = await pool.query(
          `SELECT pr.id, pr.user_id, pr.expires_at, pr.used
          FROM password_resets pr
          WHERE pr.token = $1`,
          [token]
        );

        if (tokenResult.rows.length === 0) {
          return res.status(400).json({ error: 'Token inválido' });
        }

        const resetData = tokenResult.rows[0];

        // Verificar expiración o si ya fue usado
        if (resetData.used || new Date(resetData.expires_at) < new Date()) {
          return res.status(400).json({ error: 'Token expirado o inválido' });
        }

        // Hashear nueva contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Actualizar contraseña
        await pool.query(`UPDATE usuarios SET password = $1 WHERE id = $2`, [
          hashedPassword,
          resetData.user_id,
        ]);

        // Marcar token como usado
        await pool.query(`UPDATE password_resets SET used = TRUE WHERE id = $1`, [resetData.id]);

        res.json({ message: 'Contraseña restablecida con éxito' });
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error en el servidor' });
      }
  });


  // ===================================================
  // Generar token JWT y login  
  // ===================================================
  
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Correo y contraseña son requeridos' });
      }

      // Buscar usuario
      const userResult = await pool.query(
        `SELECT u.id, u.nombres, u.apellidos, u.email, u.password, 
                u.estado, u.fk_rol, r.nombre_rol as rol
        FROM usuarios u
        JOIN roles r ON u.fk_rol = r.id
        WHERE u.email = $1`,
        [email]
      );

      if (userResult.rows.length === 0) {
        return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      const user = userResult.rows[0];

      if (user.estado !== 'activo') {
        return res.status(403).json({ error: 'Usuario inactivo. Contacte al administrador.' });
      }

      // Verificar contraseña
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      // Crear token JWT
      const token = jwt.sign(
        { 
          userId: user.id, 
          email: user.email,   // ✅ corregido
          rol: user.rol,
          rolId: user.fk_rol   // ✅ corregido
        },
        process.env.JWT_SECRET,
        { expiresIn: '10h' }
      );

      // Datos de usuario correctos
      const userData = {
        id: user.id,
        nombre: `${user.nombres} ${user.apellidos}`, // ✅ corregido
        email: user.email,
        rol: user.rol,
        rolId: user.fk_rol
      };

      res.json({ token, user: userData });

    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error en el servidor' });
    }
  });

  // Endpoint para verificar token
  app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ 
      valid: true, 
      user: {
        id: req.user.userId,
        email: req.user.email,
        rolId: req.user.rolId
      }
    });
  });


  // Endpoint para obtener datos del usuario
  app.get('/api/usuarios/me', authenticateToken, async (req, res) => {
    console.log('User ID from token:', req.user.userId);

    try {
      const userId = req.user.userId;

      if (!userId || isNaN(userId)) {
        return res.status(400).json({ error: 'ID de usuario inválido' });
      }

      const result = await pool.query(`
        SELECT 
          u.id,
          u.nombres,
          u.apellidos,
          u.email,
          u.fk_comite AS "comiteId",
          c.nombre AS "comiteNombre",
          u.fk_rol AS "rolId",
          r.nombre_rol AS rol,
          u.estado
        FROM usuarios u
        LEFT JOIN roles r ON u.fk_rol = r.id
        LEFT JOIN comite c ON u.fk_comite = c.id
        WHERE u.id = $1
      `, [userId]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const user = result.rows[0];

      if (user.estado !== 'activo') {
        return res.status(403).json({ error: 'Usuario inactivo' });
      }

      const userData = {
        id: user.id,
        nombres: user.nombres || '',
        apellidos: user.apellidos || '',
        email: user.email || '',
        rol: user.rol || '',
        rolId: user.rolId || null,
        comiteId: user.comiteId || null,
        comiteNombre: user.comiteNombre || '',
        estado: user.estado || ''
      };

      console.log('Datos enviados al frontend:', userData);
      res.json(userData);

    } catch (err) {
      console.error('Error en endpoint /api/usuarios/me:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });


  // ===================================================
  // registro de usuarios
  // ===================================================
  

  //POST /api/register
  app.post('/api/register', async (req, res) => {
    try {
      console.log('Body recibido:', req.body); // <-- esto nos dice qué datos llegan
      const { nombres, apellidos, email, password, fk_rol, fk_comite } = req.body;

      if (!nombres || !apellidos || !email || !password || !fk_rol) {
        return res.status(400).json({ error: 'Datos incompletos' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      console.log('Password hasheado:', hashedPassword);

      const result = await pool.query(
        `INSERT INTO usuarios (nombres, apellidos, email, password, fk_rol, fk_comite)
        VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, nombres, apellidos, email, fk_rol, fk_comite`,
        [nombres, apellidos, email, hashedPassword, fk_rol, fk_comite || null]
      );

      console.log('Resultado de la consulta:', result.rows[0]);
      return res.json({ message: 'Usuario creado', user: result.rows[0] });
    } catch (err) {
      console.error('Error interno:', err);
      res.status(500).json({ error: 'Error creando usuario' });
    }
  });

  // ===================================================
  // roles y permisos
  // ===================================================


  app.get('/api/users', authenticateToken, authorizeRoles('1'), async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT u.id, u.nombres, u.apellidos, u.email, r.nombre_rol as rol
        FROM usuarios u
        JOIN roles r ON u.fk_rol = r.id`
      );
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error obteniendo usuarios' });
    }
  });

  // ===================================================
  // COMITE ACTUALIZADO
  // ===================================================

 // PUT /api/usuarios/:id - Actualizar usuario
  app.put('/api/usuarios/:id', authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
      const { nombres, apellidos, comiteId } = req.body;

      // Verifica que el usuario exista
      const userCheck = await pool.query('SELECT id FROM usuarios WHERE id = $1', [id]);
      if (userCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      // Seguridad: solo dueño del perfil o rol admin (rolId = 1)
      if (req.user.userId !== parseInt(id) && req.user.rolId !== 1) {
        return res.status(403).json({ error: 'No tienes permisos para actualizar este perfil' });
      }

      // Actualiza y devuelve datos
      const result = await pool.query(`
        UPDATE usuarios 
        SET nombres = $1, apellidos = $2, fk_comite = $3, fecha_actualizacion = CURRENT_TIMESTAMP
        WHERE id = $4
        RETURNING id, nombres, apellidos, fk_comite as "comiteId",
          (SELECT nombre FROM comite WHERE id = fk_comite) as "comiteNombre";
      `, [nombres, apellidos, comiteId || null, id]);

      res.json({ 
        message: 'Usuario actualizado correctamente', 
        user: result.rows[0] 
      });

    } catch (err) {
      console.error('Error actualizando usuario:', err);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

  // GET /api/comites - Obtener lista de comités activos
  app.get('/api/comites', authenticateToken, async (req, res) => {
    try {
      const result = await pool.query(`
        SELECT id, nombre, epoca 
        FROM comite 
        WHERE estado = 'activo' 
        ORDER BY nombre
      `);
      
      res.json(result.rows);
    } catch (err) {
      console.error('Error obteniendo comités:', err);
      res.status(500).json({ error: 'Error obteniendo comités' });
    }
  });


  // Crear monto
  app.post("/api/montos", authenticateToken, upload.single("voucher"), async (req, res) => {
    try {
      const { fecha, tipo_de_cuenta, actividad, codigo, cantidad } = req.body;
      const userId = req.user.userId;

      if (!fecha || !tipo_de_cuenta || !actividad || !cantidad) {
        return res.status(400).json({ error: "Datos incompletos" });
      }

      const cantidadNum = parseFloat(cantidad);
      if (isNaN(cantidadNum) || cantidadNum <= 0) {
        return res.status(400).json({ error: "Cantidad inválida" });
      }

      const result = await pool.query(
        `INSERT INTO monto (fk_usuario, fecha, tipo_de_cuenta, actividad, codigo, voucher, cantidad)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *`,
        [
          userId,
          fecha,
          tipo_de_cuenta,
          actividad,
          codigo?.trim() || null,
          req.file ? req.file.buffer : null,
          cantidadNum,
        ]
      );

      res.json(result.rows[0]);
    } catch (err) {
      console.error("Error insertando monto:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  });

    // Obtener todos los montos del usuario

app.get("/api/montos", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(
      `SELECT id, fecha, tipo_de_cuenta, actividad, codigo, cantidad::float8 as cantidad, voucher
       FROM monto
       WHERE fk_usuario = $1
       ORDER BY fecha DESC;`,
      [userId]
    );

    const rows = await Promise.all(result.rows.map(async (r) => {
      if (!r.voucher) return { ...r, voucher: null };

      const mime = await FileType.fromBuffer(r.voucher);
      return {
        ...r,
        voucher: `data:${mime?.mime || "application/octet-stream"};base64,${r.voucher.toString("base64")}`,
      };
    }));

    res.json(rows);
  } catch (err) {
    console.error("Error obteniendo montos:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

  // Actualizar monto
  app.put("/api/montos/:id", authenticateToken, upload.single("voucher"), async (req, res) => {
    try {
      const { id } = req.params;
      const { fecha, tipo_de_cuenta, actividad, codigo, cantidad } = req.body;
      const userId = req.user.userId;

      if (!fecha || !tipo_de_cuenta || !actividad || !cantidad) {
        return res.status(400).json({ error: "Datos incompletos" });
      }

      const cantidadNum = parseFloat(cantidad);
      if (isNaN(cantidadNum) || cantidadNum <= 0) {
        return res.status(400).json({ error: "Cantidad inválida" });
      }

      const voucher = req.file ? req.file.buffer : undefined;

      const result = await pool.query(
        `UPDATE monto
        SET fecha=$1,
            tipo_de_cuenta=$2,
            actividad=$3,
            codigo=$4,
            voucher=COALESCE($5, voucher),
            cantidad=$6
        WHERE id=$7 AND fk_usuario=$8
        RETURNING *`,
        [
          fecha,
          tipo_de_cuenta,
          actividad,
          codigo?.trim() || null,
          voucher, // $5
          cantidadNum, // $6
          id, // $7
          userId // $8
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Monto no encontrado" });
      }

      res.json(result.rows[0]);
    } catch (err) {
      console.error("Error actualizando monto:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  });

  // Eliminar monto
  app.delete("/api/montos/:id", authenticateToken, async (req, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.userId;

      const result = await pool.query(
        `DELETE FROM monto WHERE id=$1 AND fk_usuario=$2 RETURNING *`,
        [id, userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Monto no encontrado" });
      }

      res.json({ message: "Monto eliminado correctamente" });
    } catch (err) {
      console.error("Error eliminando monto:", err);
      res.status(500).json({ error: "Error en el servidor" });
    }
  });




  // ===================================================
  // ROUTES MONTOS
  // ===================================================
  app.use("/api", router_monto)
  // ===================================================
  // ROUTES COMITE
  // ===================================================
  app.use("/api", router_comite)
  // ===================================================
  // ROUTES ROLES
  // ===================================================
  app.use("/api", router_roles)