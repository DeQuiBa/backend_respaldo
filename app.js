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
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
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
      const { email } = req.body;

      if (!email) return res.status(400).json({ error: 'Email requerido' });

      // Buscar usuario
      const result = await pool.query('SELECT id, email FROM usuarios WHERE email = $1', [email]);
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const user = result.rows[0];

      // Generar token
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutos

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
              MASHA-SGF
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

      await enviarCorreo(user.email, 'Recuperación de contraseña - MASHA-SGF', html);

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


  // ---------------------------------
  // USUARIOS
  //------------------------------------

  // GET /api/usuarios
  app.get('/api/usuarios', authenticateToken, authorizeRoles(1), async (req, res) => { 
    try {
      const result = await pool.query(`
        SELECT u.id, u.nombres, u.apellidos, u.email, u.estado, 
              r.nombre_rol as rol, r.id as "rolId",
              c.nombre as "comiteNombre"
        FROM usuarios u
        LEFT JOIN roles r ON u.fk_rol = r.id
        LEFT JOIN comite c ON u.fk_comite = c.id
        ORDER BY u.id ASC
      `);
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Error obteniendo usuarios' });
    }
  });

      // PUT /api/usuarios/:id/rol
    app.put('/api/usuarios/:id/rol', authenticateToken, authorizeRoles(1), async (req, res) => {
      try {
        const { id } = req.params;
        const { rolId } = req.body;

        const result = await pool.query(`
          UPDATE usuarios 
          SET fk_rol = $1, fecha_actualizacion = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING id, nombres, apellidos, email, fk_rol as "rolId"
        `, [rolId, id]);

        if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });

        res.json({ message: "Rol actualizado", user: result.rows[0] });
      } catch (err) {
        console.error("Error cambiando rol:", err);
        res.status(500).json({ error: "Error interno del servidor" });
      }
    });

    // PUT /api/usuarios/:id/estado
    app.put('/api/usuarios/:id/estado', authenticateToken, authorizeRoles(1), async (req, res) => {
      try {
        const { id } = req.params;
        const { estado } = req.body; // "activo" o "inactivo"

        if (!['activo', 'inactivo'].includes(estado)) {
          return res.status(400).json({ error: "Estado inválido" });
        }

        const result = await pool.query(`
          UPDATE usuarios 
          SET estado = $1, fecha_actualizacion = CURRENT_TIMESTAMP
          WHERE id = $2
          RETURNING id, nombres, apellidos, email, estado
        `, [estado, id]);

        if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });

        res.json({ message: "Estado actualizado", user: result.rows[0] });
      } catch (err) {
        console.error("Error cambiando estado:", err);
        res.status(500).json({ error: "Error interno del servidor" });
      }
    });


    // GET /api/usuarios/:id/montos
    app.get('/api/usuarios/:id/montos', authenticateToken, authorizeRoles(1, 64), async (req, res) => {
      try {
        const { id } = req.params;

        const result = await pool.query(`
          SELECT m.id, 
                m.fecha, 
                m.tipo_de_cuenta, 
                m.actividad, 
                m.codigo, 
                m.cantidad::float8 as cantidad, 
                encode(m.voucher, 'base64') as voucher  -- 👈 conversión a base64
          FROM monto m
          WHERE m.fk_usuario = $1
          ORDER BY m.fecha DESC
        `, [id]);

        res.json(result.rows);
      } catch (err) {
        console.error("Error obteniendo montos de usuario:", err);
        res.status(500).json({ error: "Error en el servidor" });
      }
    });


    // GET /api/usuarios/:id/montos/resumen
    app.get('/api/usuarios/:id/montos/resumen', authenticateToken, authorizeRoles(1), async (req, res) => {
      try {
        const { id } = req.params;

        const result = await pool.query(`
          SELECT 
            SUM(CASE WHEN tipo_de_cuenta = 'Ingreso' THEN cantidad ELSE 0 END)::float8 as ingresos,
            SUM(CASE WHEN tipo_de_cuenta = 'Egreso' THEN cantidad ELSE 0 END)::float8 as egresos,
            (SUM(CASE WHEN tipo_de_cuenta = 'Ingreso' THEN cantidad ELSE 0 END) -
            SUM(CASE WHEN tipo_de_cuenta = 'Egreso' THEN cantidad ELSE 0 END))::float8 as balance
          FROM monto
          WHERE fk_usuario = $1
        `, [id]);

        res.json(result.rows[0]);
      } catch (err) {
        console.error("Error obteniendo resumen de montos:", err);
        res.status(500).json({ error: "Error en el servidor" });
      }
    });

    // DELETE /api/usuarios/:id
    app.delete('/api/usuarios/:id', authenticateToken, authorizeRoles(1), async (req, res) => {
      try {
        const { id } = req.params;

        const result = await pool.query(`
          DELETE FROM usuarios
          WHERE id = $1
          RETURNING id
        `, [id]);

        if (result.rows.length === 0) {
          return res.status(404).json({ error: "Usuario no encontrado" });
        }

        res.json({ message: "Usuario eliminado exitosamente" });
      } catch (err) {
        console.error("Error eliminando usuario:", err);
        res.status(500).json({ error: "Error interno del servidor" });
      }
    });






        /* --------------------- CRUD COMITE --------------------- */

      // GET /api/comites -> listar todos los comites
      app.get('/api/allcomites', authenticateToken, authorizeRoles(1), async (req, res) => {
        try {
          const result = await pool.query(`
            SELECT id, nombre, epoca, estado
            FROM comite
            ORDER BY id ASC
          `);
          res.json(result.rows);
        } catch (err) {
          console.error("Error obteniendo comités:", err);
          res.status(500).json({ error: "Error en el servidor" });
        }
      });

      // GET /api/comites/:id -> obtener un comité por ID
      app.get('/api/comites/:id', authenticateToken, authorizeRoles(1), async (req, res) => {
        try {
          const { id } = req.params;
          const result = await pool.query(`
            SELECT id, nombre, epoca, estado
            FROM comite
            WHERE id = $1
          `, [id]);

          if (result.rows.length === 0) return res.status(404).json({ error: "Comité no encontrado" });
          res.json(result.rows[0]);
        } catch (err) {
          console.error("Error obteniendo comité:", err);
          res.status(500).json({ error: "Error en el servidor" });
        }
      });

      // POST /api/comites -> crear un nuevo comité
      app.post('/api/comites', authenticateToken, authorizeRoles(1), async (req, res) => {
        try {
          const { nombre, epoca, estado } = req.body;
          if (!nombre || !epoca) return res.status(400).json({ error: "Nombre y época son requeridos" });
          if (estado && !['activo','inactivo'].includes(estado)) return res.status(400).json({ error: "Estado inválido" });

          const result = await pool.query(`
            INSERT INTO comite (nombre, epoca, estado)
            VALUES ($1, $2, COALESCE($3,'activo'))
            RETURNING id, nombre, epoca, estado
          `, [nombre, epoca, estado]);

          res.status(201).json({ message: "Comité creado", comite: result.rows[0] });
        } catch (err) {
          console.error("Error creando comité:", err);
          res.status(500).json({ error: "Error en el servidor" });
        }
      });

      // PUT /api/comites/:id -> actualizar comité
      app.put('/api/comites/:id', authenticateToken, authorizeRoles(1), async (req, res) => {
        try {
          const { id } = req.params;
          const { nombre, epoca, estado } = req.body;
          if (!nombre && !epoca && !estado) return res.status(400).json({ error: "Debe enviar al menos un campo a actualizar" });
          if (estado && !['activo','inactivo'].includes(estado)) return res.status(400).json({ error: "Estado inválido" });

          const result = await pool.query(`
            UPDATE comite
            SET 
              nombre = COALESCE($1, nombre),
              epoca = COALESCE($2, epoca),
              estado = COALESCE($3, estado)
            WHERE id = $4
            RETURNING id, nombre, epoca, estado
          `, [nombre, epoca, estado, id]);

          if (result.rows.length === 0) return res.status(404).json({ error: "Comité no encontrado" });
          res.json({ message: "Comité actualizado", comite: result.rows[0] });
        } catch (err) {
          console.error("Error actualizando comité:", err);
          res.status(500).json({ error: "Error en el servidor" });
        }
      });

      // DELETE /api/comites/:id -> eliminar comité
      app.delete('/api/comites/:id', authenticateToken, authorizeRoles(1), async (req, res) => {
        try {
          const { id } = req.params;
          const result = await pool.query(`
            DELETE FROM comite
            WHERE id = $1
            RETURNING id
          `, [id]);

          if (result.rows.length === 0) return res.status(404).json({ error: "Comité no encontrado" });
          res.json({ message: "Comité eliminado exitosamente" });
        } catch (err) {
          console.error("Error eliminando comité:", err);
          res.status(500).json({ error: "Error en el servidor" });
        }
      });




      // ===================================================
// DASHBOARD APIs - Agregar al final de server.js
// ===================================================

// ===================================================
// ESTADÍSTICAS GENERALES DEL DASHBOARD
// ===================================================

// GET /api/dashboard/stats - Estadísticas generales del sistema
app.get('/api/dashboard/stats', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM usuarios WHERE estado = 'activo') as usuarios_activos,
        (SELECT COUNT(*) FROM usuarios WHERE estado = 'inactivo') as usuarios_inactivos,
        (SELECT COUNT(*) FROM comite WHERE estado = 'activo') as comites_activos,
        (SELECT COUNT(*) FROM monto) as total_transacciones,
        (SELECT SUM(cantidad)::float8 FROM monto WHERE tipo_de_cuenta = 'Ingreso') as total_ingresos,
        (SELECT SUM(cantidad)::float8 FROM monto WHERE tipo_de_cuenta = 'Egreso') as total_egresos,
        (SELECT COUNT(*) FROM monto WHERE DATE(fecha) = CURRENT_DATE) as transacciones_hoy,
        (SELECT COUNT(*) FROM usuarios WHERE DATE(fecha_creacion) >= CURRENT_DATE - INTERVAL '30 days') as usuarios_mes
    `);
    
    const result = stats.rows[0];
    
    res.json({
      usuarios: {
        activos: parseInt(result.usuarios_activos) || 0,
        inactivos: parseInt(result.usuarios_inactivos) || 0,
        nuevos_mes: parseInt(result.usuarios_mes) || 0
      },
      comites: {
        activos: parseInt(result.comites_activos) || 0
      },
      finanzas: {
        total_ingresos: result.total_ingresos || 0,
        total_egresos: result.total_egresos || 0,
        balance: (result.total_ingresos || 0) - (result.total_egresos || 0),
        total_transacciones: parseInt(result.total_transacciones) || 0,
        transacciones_hoy: parseInt(result.transacciones_hoy) || 0
      }
    });
    
  } catch (err) {
    console.error('Error obteniendo estadísticas del dashboard:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================================================
// GRÁFICOS Y ANÁLISIS FINANCIERO
// ===================================================

// GET /api/dashboard/ingresos-egresos-mensual
app.get('/api/dashboard/ingresos-egresos-mensual', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { year } = req.query;
    const currentYear = year || new Date().getFullYear();
    
    const result = await pool.query(`
      WITH meses AS (
        SELECT generate_series(1, 12) as mes
      )
      SELECT 
        m.mes,
        COALESCE(SUM(CASE WHEN mo.tipo_de_cuenta = 'Ingreso' THEN mo.cantidad ELSE 0 END), 0)::float8 as ingresos,
        COALESCE(SUM(CASE WHEN mo.tipo_de_cuenta = 'Egreso' THEN mo.cantidad ELSE 0 END), 0)::float8 as egresos
      FROM meses m
      LEFT JOIN monto mo ON EXTRACT(MONTH FROM mo.fecha) = m.mes 
        AND EXTRACT(YEAR FROM mo.fecha) = $1
      GROUP BY m.mes
      ORDER BY m.mes
    `, [currentYear]);

    const meses = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 
                   'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic'];
    
    const data = result.rows.map(row => ({
      mes: meses[row.mes - 1],
      mes_num: row.mes,
      ingresos: row.ingresos,
      egresos: row.egresos,
      balance: row.ingresos - row.egresos
    }));

    res.json(data);
  } catch (err) {
    console.error('Error obteniendo datos mensuales:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/dashboard/transacciones-por-usuario
app.get('/api/dashboard/transacciones-por-usuario', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const result = await pool.query(`
      SELECT 
        u.nombres || ' ' || u.apellidos as nombre_completo,
        u.email,
        COUNT(m.id) as total_transacciones,
        SUM(CASE WHEN m.tipo_de_cuenta = 'Ingreso' THEN m.cantidad ELSE 0 END)::float8 as total_ingresos,
        SUM(CASE WHEN m.tipo_de_cuenta = 'Egreso' THEN m.cantidad ELSE 0 END)::float8 as total_egresos,
        (SUM(CASE WHEN m.tipo_de_cuenta = 'Ingreso' THEN m.cantidad ELSE 0 END) -
         SUM(CASE WHEN m.tipo_de_cuenta = 'Egreso' THEN m.cantidad ELSE 0 END))::float8 as balance
      FROM usuarios u
      LEFT JOIN monto m ON u.id = m.fk_usuario
      WHERE u.estado = 'activo'
      GROUP BY u.id, u.nombres, u.apellidos, u.email
      HAVING COUNT(m.id) > 0
      ORDER BY total_transacciones DESC
      LIMIT $1
    `, [limit]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo transacciones por usuario:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/dashboard/actividades-frecuentes
app.get('/api/dashboard/actividades-frecuentes', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const result = await pool.query(`
      SELECT 
        actividad,
        tipo_de_cuenta,
        COUNT(*) as frecuencia,
        SUM(cantidad)::float8 as monto_total,
        AVG(cantidad)::float8 as monto_promedio
      FROM monto
      GROUP BY actividad, tipo_de_cuenta
      ORDER BY frecuencia DESC, monto_total DESC
      LIMIT $1
    `, [limit]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo actividades frecuentes:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/dashboard/tendencia-semanal
app.get('/api/dashboard/tendencia-semanal', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        DATE_TRUNC('week', fecha) as semana,
        COUNT(*) as transacciones,
        SUM(CASE WHEN tipo_de_cuenta = 'Ingreso' THEN cantidad ELSE 0 END)::float8 as ingresos,
        SUM(CASE WHEN tipo_de_cuenta = 'Egreso' THEN cantidad ELSE 0 END)::float8 as egresos
      FROM monto
      WHERE fecha >= CURRENT_DATE - INTERVAL '12 weeks'
      GROUP BY DATE_TRUNC('week', fecha)
      ORDER BY semana DESC
    `);

    const data = result.rows.map(row => ({
      semana: row.semana.toISOString().split('T')[0],
      transacciones: parseInt(row.transacciones),
      ingresos: row.ingresos,
      egresos: row.egresos,
      balance: row.ingresos - row.egresos
    }));

    res.json(data);
  } catch (err) {
    console.error('Error obteniendo tendencia semanal:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/dashboard/distribucion-por-comite - VERSIÓN CORREGIDA
app.get('/api/dashboard/distribucion-por-comite', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        c.id,
        c.nombre as comite,
        c.epoca,
        c.estado,
        COUNT(DISTINCT u.id) as total_usuarios,  -- Cambiado de usuarios_activos a total_usuarios
        COUNT(DISTINCT CASE WHEN u.estado = 'activo' THEN u.id END) as usuarios_activos,  -- Mantener contador de activos
        COUNT(m.id) as total_transacciones,
        COALESCE(SUM(CASE WHEN m.tipo_de_cuenta = 'Ingreso' THEN m.cantidad ELSE 0 END),0)::float8 as ingresos,
        COALESCE(SUM(CASE WHEN m.tipo_de_cuenta = 'Egreso' THEN m.cantidad ELSE 0 END),0)::float8 as egresos
      FROM comite c
      LEFT JOIN usuarios u ON c.id = u.fk_comite  -- REMOVIDO: AND u.estado = 'activo'
      LEFT JOIN monto m ON u.id = m.fk_usuario
      GROUP BY c.id, c.nombre, c.epoca, c.estado
      ORDER BY ingresos DESC
    `);

    const data = result.rows.map(row => ({
      id: row.id,
      comite: row.comite,
      epoca: row.epoca,
      estado: row.estado,
      usuarios_activos: parseInt(row.usuarios_activos) || 0,
      total_usuarios: parseInt(row.total_usuarios) || 0,  // Nuevo campo
      total_transacciones: parseInt(row.total_transacciones) || 0,
      ingresos: row.ingresos || 0,
      egresos: row.egresos || 0,
      balance: (row.ingresos || 0) - (row.egresos || 0)
    }));

    res.json(data);
  } catch (err) {
    console.error('Error obteniendo distribución por comité:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});


// GET /api/dashboard/ultimas-transacciones
app.get('/api/dashboard/ultimas-transacciones', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    
    const result = await pool.query(`
      SELECT 
        m.id,
        m.fecha,
        m.tipo_de_cuenta,
        m.actividad,
        m.codigo,
        m.cantidad::float8,
        u.nombres || ' ' || u.apellidos as usuario,
        u.email,
        c.nombre as comite
      FROM monto m
      JOIN usuarios u ON m.fk_usuario = u.id
      LEFT JOIN comite c ON u.fk_comite = c.id
      ORDER BY m.fecha DESC, m.id DESC
      LIMIT $1
    `, [limit]);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo últimas transacciones:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================================================
// REPORTES AVANZADOS
// ===================================================

// GET /api/dashboard/reporte-periodo
app.get('/api/dashboard/reporte-periodo', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { fecha_inicio, fecha_fin, comite_id, usuario_id } = req.query;
    
    if (!fecha_inicio || !fecha_fin) {
      return res.status(400).json({ error: 'Fechas de inicio y fin son requeridas' });
    }

    let whereClause = 'WHERE m.fecha BETWEEN $1 AND $2';
    let params = [fecha_inicio, fecha_fin];
    let paramCount = 2;

    if (comite_id) {
      paramCount++;
      whereClause += ` AND u.fk_comite = $${paramCount}`;
      params.push(comite_id);
    }

    if (usuario_id) {
      paramCount++;
      whereClause += ` AND m.fk_usuario = $${paramCount}`;
      params.push(usuario_id);
    }

    // Resumen de transacciones
    const result = await pool.query(`
      SELECT 
        COUNT(*) as total_transacciones,
        COUNT(DISTINCT m.fk_usuario) as usuarios_involucrados,
        SUM(CASE WHEN m.tipo_de_cuenta = 'Ingreso' THEN m.cantidad ELSE 0 END)::float8 as total_ingresos,
        SUM(CASE WHEN m.tipo_de_cuenta = 'Egreso' THEN m.cantidad ELSE 0 END)::float8 as total_egresos,
        AVG(CASE WHEN m.tipo_de_cuenta = 'Ingreso' THEN m.cantidad END)::float8 as promedio_ingresos,
        AVG(CASE WHEN m.tipo_de_cuenta = 'Egreso' THEN m.cantidad END)::float8 as promedio_egresos,
        MAX(m.cantidad)::float8 as transaccion_mayor,
        MIN(m.cantidad)::float8 as transaccion_menor,
        COUNT(CASE WHEN m.estado_voucher = 'pendiente' THEN 1 END) as vouchers_pendientes,
        COUNT(CASE WHEN m.estado_voucher = 'valido' THEN 1 END) as vouchers_validos,
        COUNT(CASE WHEN m.estado_voucher = 'invalido' THEN 1 END) as vouchers_invalidos
      FROM monto m
      JOIN usuarios u ON m.fk_usuario = u.id
      ${whereClause}
    `, params);

    // Listado de transacciones (incluyendo voucher y estado)
    const transacciones = await pool.query(`
      SELECT 
        m.id,
        m.fecha,
        m.tipo_de_cuenta,
        m.actividad,
        m.codigo,
        m.cantidad::float8,
        m.voucher,
        m.estado_voucher,
        u.nombres || ' ' || u.apellidos as usuario,
        c.nombre as comite
      FROM monto m
      JOIN usuarios u ON m.fk_usuario = u.id
      LEFT JOIN comite c ON u.fk_comite = c.id
      ${whereClause}
      ORDER BY m.fecha DESC, m.id DESC
    `, params);

    // Convertir voucher bytea -> Base64
    const transaccionesConVoucher = await Promise.all(transacciones.rows.map(async (t) => {
      if (!t.voucher) return { ...t, voucher: null };
      
      const mime = await FileType.fromBuffer(t.voucher);
      return {
        ...t,
        voucher: `data:${mime?.mime || "application/octet-stream"};base64,${t.voucher.toString("base64")}`,
      };
    }));

    const resumen = result.rows[0];
    
    res.json({
      resumen: {
        total_transacciones: parseInt(resumen.total_transacciones) || 0,
        usuarios_involucrados: parseInt(resumen.usuarios_involucrados) || 0,
        total_ingresos: resumen.total_ingresos || 0,
        total_egresos: resumen.total_egresos || 0,
        balance: (resumen.total_ingresos || 0) - (resumen.total_egresos || 0),
        promedio_ingresos: resumen.promedio_ingresos || 0,
        promedio_egresos: resumen.promedio_egresos || 0,
        transaccion_mayor: resumen.transaccion_mayor || 0,
        transaccion_menor: resumen.transaccion_menor || 0,
        vouchers_pendientes: parseInt(resumen.vouchers_pendientes) || 0,
        vouchers_validos: parseInt(resumen.vouchers_validos) || 0,
        vouchers_invalidos: parseInt(resumen.vouchers_invalidos) || 0
      },
      transacciones: transaccionesConVoucher,
      filtros: {
        fecha_inicio,
        fecha_fin,
        comite_id: comite_id || null,
        usuario_id: usuario_id || null
      }
    });
   
  } catch (err) {
    console.error('Error generando reporte de período:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// PATCH /api/monto/:id/estado - Cambiar estado del voucher
app.patch('/api/monto/:id/estado', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { id } = req.params;
    const { estado_voucher } = req.body;

    // Validar que el estado sea válido
    const estadosValidos = ['pendiente', 'valido', 'invalido'];
    if (!estado_voucher || !estadosValidos.includes(estado_voucher)) {
      return res.status(400).json({ 
        error: 'Estado inválido. Debe ser: pendiente, valido o invalido' 
      });
    }

    // Verificar que el monto existe
    const verificar = await pool.query(
      'SELECT id FROM monto WHERE id = $1',
      [id]
    );

    if (verificar.rows.length === 0) {
      return res.status(404).json({ error: 'Monto no encontrado' });
    }

    // Actualizar el estado
    const resultado = await pool.query(
      `UPDATE monto 
       SET estado_voucher = $1 
       WHERE id = $2 
       RETURNING id, estado_voucher, fecha, actividad, cantidad::float8`,
      [estado_voucher, id]
    );

    res.json({
      mensaje: 'Estado actualizado correctamente',
      monto: resultado.rows[0]
    });

  } catch (err) {
    console.error('Error actualizando estado del voucher:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/monto/:id - Obtener detalles de un monto específico
app.get('/api/monto/:id', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { id } = req.params;

    const resultado = await pool.query(`
      SELECT 
        m.id,
        m.fecha,
        m.tipo_de_cuenta,
        m.actividad,
        m.codigo,
        m.cantidad::float8,
        m.estado_voucher,
        m.voucher,
        u.nombres || ' ' || u.apellidos as usuario,
        c.nombre as comite
      FROM monto m
      JOIN usuarios u ON m.fk_usuario = u.id
      LEFT JOIN comite c ON u.fk_comite = c.id
      WHERE m.id = $1
    `, [id]);

    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Monto no encontrado' });
    }

    const monto = resultado.rows[0];

    // Convertir voucher si existe
    if (monto.voucher) {
      const mime = await FileType.fromBuffer(monto.voucher);
      monto.voucher = `data:${mime?.mime || "application/octet-stream"};base64,${monto.voucher.toString("base64")}`;
    }

    res.json(monto);

  } catch (err) {
    console.error('Error obteniendo monto:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================================================
// MÉTRICAS DE RENDIMIENTO
// ===================================================

// GET /api/dashboard/metricas-rendimiento
app.get('/api/dashboard/metricas-rendimiento', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const result = await pool.query(`
      WITH fecha_actual AS (SELECT CURRENT_DATE as hoy),
      mes_actual AS (
        SELECT COUNT(*) as transacciones_mes,
               SUM(cantidad)::float8 as monto_mes
        FROM monto, fecha_actual
        WHERE EXTRACT(MONTH FROM fecha) = EXTRACT(MONTH FROM hoy)
          AND EXTRACT(YEAR FROM fecha) = EXTRACT(YEAR FROM hoy)
      ),
      mes_anterior AS (
        SELECT COUNT(*) as transacciones_mes_ant,
               SUM(cantidad)::float8 as monto_mes_ant
        FROM monto, fecha_actual
        WHERE fecha >= (hoy - INTERVAL '1 month')::date
          AND fecha < DATE_TRUNC('month', hoy)
      ),
      usuarios_activos_mes AS (
        SELECT COUNT(DISTINCT fk_usuario) as usuarios_activos
        FROM monto, fecha_actual
        WHERE fecha >= DATE_TRUNC('month', hoy)
      )
      SELECT 
        ma.transacciones_mes,
        ma.monto_mes,
        mant.transacciones_mes_ant,
        mant.monto_mes_ant,
        uam.usuarios_activos,
        CASE 
          WHEN mant.transacciones_mes_ant > 0 THEN
            ROUND(((ma.transacciones_mes - mant.transacciones_mes_ant)::float8 / mant.transacciones_mes_ant * 100), 2)
          ELSE 0
        END as crecimiento_transacciones,
        CASE 
          WHEN mant.monto_mes_ant > 0 THEN
            ROUND(((ma.monto_mes - mant.monto_mes_ant) / mant.monto_mes_ant * 100), 2)
          ELSE 0
        END as crecimiento_monto
      FROM mes_actual ma, mes_anterior mant, usuarios_activos_mes uam
    `);

    res.json(result.rows[0] || {});
  } catch (err) {
    console.error('Error obteniendo métricas de rendimiento:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================================================
// AUDITORÍA Y LOGS
// ===================================================

// GET /api/dashboard/auditoria
app.get('/api/dashboard/auditoria', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { limit = 50, tabla, accion } = req.query;
    
    let whereClause = '';
    let params = [];
    let paramCount = 0;

    if (tabla) {
      paramCount++;
      whereClause += `WHERE tabla = $${paramCount}`;
      params.push(tabla);
    }

    if (accion) {
      paramCount++;
      whereClause += `${whereClause ? ' AND' : 'WHERE'} accion = $${paramCount}`;
      params.push(accion);
    }

    paramCount++;
    params.push(limit);

    const result = await pool.query(`
      SELECT 
        id,
        tabla,
        accion,
        usuario,
        fecha,
        datos_anteriores,
        datos_nuevos
      FROM auditoria
      ${whereClause}
      ORDER BY fecha DESC, id DESC
      LIMIT $${paramCount}
    `, params);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo auditoría:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/dashboard/auditoria/resumen
app.get('/api/dashboard/auditoria/resumen', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        tabla,
        accion,
        COUNT(*) as cantidad,
        MAX(fecha) as ultima_accion
      FROM auditoria
      WHERE fecha >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY tabla, accion
      ORDER BY cantidad DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error('Error obteniendo resumen de auditoría:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================================================
// EXPORTACIÓN DE DATOS
// ===================================================

// GET /api/dashboard/exportar/csv
app.get('/api/dashboard/exportar/csv', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { tipo, fecha_inicio, fecha_fin } = req.query;
    
    if (!tipo || !['transacciones', 'usuarios', 'comites'].includes(tipo)) {
      return res.status(400).json({ error: 'Tipo de exportación inválido' });
    }

    let query = '';
    let params = [];

    switch (tipo) {
      case 'transacciones':
        query = `
          SELECT 
            m.fecha,
            m.tipo_de_cuenta,
            m.actividad,
            m.codigo,
            m.cantidad,
            u.nombres || ' ' || u.apellidos as usuario,
            u.email,
            c.nombre as comite
          FROM monto m
          JOIN usuarios u ON m.fk_usuario = u.id
          LEFT JOIN comite c ON u.fk_comite = c.id
        `;
        if (fecha_inicio && fecha_fin) {
          query += ' WHERE m.fecha BETWEEN $1 AND $2';
          params = [fecha_inicio, fecha_fin];
        }
        query += ' ORDER BY m.fecha DESC';
        break;
        
      case 'usuarios':
        query = `
          SELECT 
            u.nombres,
            u.apellidos,
            u.email,
            u.estado,
            r.nombre_rol as rol,
            c.nombre as comite,
            u.fecha_creacion
          FROM usuarios u
          LEFT JOIN roles r ON u.fk_rol = r.id
          LEFT JOIN comite c ON u.fk_comite = c.id
          ORDER BY u.fecha_creacion DESC
        `;
        break;
        
      case 'comites':
        query = `
          SELECT 
            nombre,
            epoca,
            estado,
            (SELECT COUNT(*) FROM usuarios WHERE fk_comite = comite.id) as usuarios_asociados
          FROM comite
          ORDER BY nombre
        `;
        break;
    }

    const result = await pool.query(query, params);
    
    // Convertir a CSV
    if (result.rows.length === 0) {
      return res.json({ error: 'No hay datos para exportar' });
    }

    const headers = Object.keys(result.rows[0]);
    let csv = headers.join(',') + '\n';
    
    result.rows.forEach(row => {
      const values = headers.map(header => {
        const value = row[header];
        if (value === null || value === undefined) return '';
        if (typeof value === 'string' && value.includes(',')) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return value;
      });
      csv += values.join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=${tipo}_${new Date().toISOString().split('T')[0]}.csv`);
    res.send(csv);

  } catch (err) {
    console.error('Error exportando datos:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});


// Buscar monto por código
app.get('/api/monto/:codigo', async (req, res) => {
  const { codigo } = req.params;

  try {
    if (!codigo) {
      return res.status(400).json({ error: 'El código es requerido' });
    }

    // Normalizamos el código en la búsqueda (case-insensitive y sin espacios extras)
    const result = await pool.query(
      `
      SELECT 
        m.id,
        m.fecha,
        m.tipo_de_cuenta,
        m.actividad,
        m.codigo,
        m.cantidad,
        encode(m.voucher, 'base64') AS voucher, -- bytea convertido a base64
        u.id AS "usuarioId",
        u.nombres AS "usuarioNombre",
        u.apellidos AS "usuarioApellidos",
        u.email AS "usuarioEmail",
        c.id AS "comiteId",
        c.nombre AS "comiteNombre"
      FROM monto m
      LEFT JOIN usuarios u ON m.fk_usuario = u.id
      LEFT JOIN comite c ON u.fk_comite = c.id
      WHERE TRIM(LOWER(m.codigo)) = TRIM(LOWER($1))
      `,
      [codigo]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: `No se encontró ningún monto con el código: ${codigo}` });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error en endpoint /api/monto/:codigo:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ====================================================================
// VER VOUCHER (IMAGEN) - SERVIR IMÁGENES DESDE BYTEA -- ENLACE DIRECTO
// ===================================================================


app.get("/api/montos/:id/voucher", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT voucher FROM monto WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0 || !result.rows[0].voucher) {
      return res.status(404).json({ error: "Voucher no encontrado" });
    }

    const voucherBuffer = result.rows[0].voucher;

    const mime = await FileType.fromBuffer(voucherBuffer);
    const mimeType = mime?.mime || "image/jpeg";

    res.setHeader("Content-Type", mimeType);
    res.setHeader(
      "Content-Disposition",
      `inline; filename="voucher-${id}.${mime?.ext || "jpg"}"`
    );
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.send(voucherBuffer);
  } catch (err) {
    console.error("Error obteniendo voucher:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ✅ Ruta pública para obtener información del voucher
app.get("/api/montos/:id/voucher/info", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT 
        CASE 
          WHEN voucher IS NOT NULL THEN true 
          ELSE false 
        END as has_voucher,
        CASE 
          WHEN voucher IS NOT NULL THEN octet_length(voucher)
          ELSE 0 
        END as size_bytes,
        actividad,
        fecha
      FROM monto 
      WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Transacción no encontrada" });
    }

    const row = result.rows[0];
    res.json({
      hasVoucher: row.has_voucher,
      sizeBytes: row.size_bytes,
      sizeMB: (row.size_bytes / 1024 / 1024).toFixed(2),
      actividad: row.actividad,
      fecha: row.fecha,
      voucherUrl: row.has_voucher ? `/api/montos/${id}/voucher` : null
    });

  } catch (err) {
    console.error("Error obteniendo información del voucher:", err);
    res.status(500).json({ error: "Error en el servidor" });
  }
});


/*Obtener detalles de un monto para búsqueda*/


// GET /api/monto/codigo/:codigo - Obtener detalles de un monto por su código
app.get('/api/monto/codigo/:codigo', authenticateToken, authorizeRoles(1), async (req, res) => {
  try {
    const { codigo } = req.params;

    if (!codigo) {
      return res.status(400).json({ error: 'El código del monto es requerido' });
    }

    // Buscar monto con información detallada
    const result = await pool.query(`
      SELECT 
        m.id,
        m.fecha,
        m.tipo_de_cuenta,
        m.actividad,
        m.codigo,
        m.cantidad::float8,
        m.estado_voucher,
        m.voucher,
        u.nombres AS usuario_nombre,
        u.apellidos AS usuario_apellidos,
        u.email AS usuario_email,
        c.nombre AS comite
      FROM monto m
      JOIN usuarios u ON m.fk_usuario = u.id
      LEFT JOIN comite c ON u.fk_comite = c.id
      WHERE m.codigo = $1
    `, [codigo]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Monto no encontrado' });
    }

    const monto = result.rows[0];

    // Procesar el voucher
    if (monto.voucher) {
      try {
        const mime = await FileType.fromBuffer(monto.voucher);
        monto.voucher = `data:${mime?.mime || 'application/octet-stream'};base64,${monto.voucher.toString('base64')}`;
      } catch (e) {
        console.warn('Error al procesar voucher:', e);
        monto.voucher = null;
      }
    } else {
      monto.voucher = null;
    }

    // Enviar respuesta clara
    res.json({
      id: monto.id,
      fecha: monto.fecha,
      tipo_de_cuenta: monto.tipo_de_cuenta,
      actividad: monto.actividad,
      codigo: monto.codigo,
      cantidad: monto.cantidad,
      estado_voucher: monto.estado_voucher,
      voucher: monto.voucher,   // ✅ Imagen lista para <img src={...}>
      usuarioNombre: monto.usuario_nombre,
      usuarioApellidos: monto.usuario_apellidos,
      usuarioEmail: monto.usuario_email,
      comiteNombre: monto.comite
    });

  } catch (err) {
    console.error('Error obteniendo monto por código:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
