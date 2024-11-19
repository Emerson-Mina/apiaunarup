// Requerimos las dependencias necesarias
require('dotenv').config(); // Carga las variables de entorno desde el archivo .env
const express = require('express'); // Framework web para crear el servidor
const mysql = require('mysql2'); // Paquete para interactuar con MySQL
const bcrypt = require('bcryptjs'); // Para encriptar y comparar contraseñas
const jwt = require('jsonwebtoken'); // Para crear y verificar tokens JWT
const cors = require('cors'); // Paquete para habilitar CORS

// Crear una instancia de la aplicación express
const app = express();
app.use(express.json()); // Middleware para parsear el cuerpo de las solicitudes en formato JSON

// Configuración de CORS
app.use(
  cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500'], // Agrega ambos orígenes aquí
  })
);

// Configuración de la conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST, // Dirección del host de la base de datos
  user: process.env.DB_USER, // Usuario de la base de datos
  password: process.env.DB_PASSWORD, // Contraseña de la base de datos
  database: process.env.DB_NAME, // Nombre de la base de datos
});

// Intentar conectar a la base de datos
db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err.message);
    process.exit(1); // Termina el proceso si la conexión falla
  } else {
    console.log('Conectado a la base de datos MySQL');
  }
});

// Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extraemos el token del encabezado Authorization

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Acceso denegado: se requiere autenticación',
    });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: 'Token no válido o expirado',
      });
    }
    req.user = decoded; // Decodificamos el token y guardamos la información del usuario en el objeto req
    next();
  });
};

// Middleware para verificar si el usuario es administrador
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Acceso denegado: solo los administradores pueden acceder a esta ruta',
    });
  }
  next();
};

// Ruta para registrar un nuevo usuario
app.post('/register', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const {
      username,
      password,
      role,
      first_name,
      last_name,
      birth_date,
      academic_program,
      semester,
      phone_number,
      institutional_email,
    } = req.body;

    // Validar que todos los campos estén presentes
    if (
      !username ||
      !password ||
      !role ||
      !first_name ||
      !last_name ||
      !birth_date ||
      !academic_program ||
      !semester ||
      !phone_number ||
      !institutional_email
    ) {
      return res.status(400).json({
        success: false,
        message: 'Por favor, proporciona todos los campos requeridos',
      });
    }

    // Verificar que el rol sea válido
    const queryRole = 'SELECT id FROM roles WHERE name = ?';
    db.query(queryRole, [role], async (err, result) => {
      if (err) throw new Error('Error al verificar rol');

      if (result.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Rol no válido. Debe ser "admin" o "user".',
        });
      }

      // Hashear la contraseña
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insertar el nuevo usuario en la base de datos
      const query = `
        INSERT INTO users 
          (username, password, role_id, first_name, last_name, birth_date, academic_program, semester, phone_number, institutional_email)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      db.query(
        query,
        [
          username,
          hashedPassword,
          result[0].id,
          first_name,
          last_name,
          birth_date,
          academic_program,
          semester,
          phone_number,
          institutional_email,
        ],
        (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({
              success: false,
              message:
                'Error al registrar el usuario. El nombre de usuario o correo institucional podría estar en uso.',
            });
          }
          res.status(201).json({
            success: true,
            message: `Usuario ${username} registrado exitosamente.`,
          });
        }
      );
    });
  } catch (err) {
    next(err); // Delegamos el error al middleware de manejo de errores
  }
});

// Ruta para obtener el perfil de usuario autenticado
app.get('/profile', verifyToken, (req, res) => {
  const query =
    'SELECT u.username, u.first_name, u.last_name, r.name AS role, u.birth_date, u.academic_program, u.semester, u.phone_number, u.institutional_email ' +
    'FROM users u ' +
    'JOIN roles r ON u.role_id = r.id ' +
    'WHERE u.id = ?';

  db.query(query, [req.user.userId], (err, results) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Error al obtener el perfil del usuario',
      });
    }

    if (results.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado',
      });
    }

    const user = results[0];

    res.json({
      success: true,
      username: user.username,          // Agregar el nombre de usuario
      firstName: user.first_name,
      lastName: user.last_name,
      userRole: user.role,
      birthDate: user.birth_date,
      academicProgram: user.academic_program,
      semester: user.semester,
      phoneNumber: user.phone_number,
      institutionalEmail: user.institutional_email,
    });
  });
});




// Ruta para restablecer la contraseña por un administrador
app.post('/reset-password', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Por favor, proporciona el nombre de usuario y la nueva contraseña',
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const query = 'UPDATE users SET password = ? WHERE username = ?';
    db.query(query, [hashedPassword, username], (err, result) => {
      if (err) throw new Error('Error al restablecer la contraseña');

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: 'Usuario no encontrado',
        });
      }

      res.status(200).json({
        success: true,
        message: `La contraseña de ${username} se ha restablecido correctamente`,
      });
    });
  } catch (err) {
    next(err);
  }
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor',
  });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
// Ruta para el login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Por favor, proporciona ambos campos: nombre de usuario y contraseña',
      });
    }

    // Buscar el usuario en la base de datos
    const query = 'SELECT u.id, u.username, u.password, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = ?';
    db.query(query, [username], async (err, results) => {
      if (err) throw new Error('Error al verificar usuario');

      if (results.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Credenciales incorrectas',
        });
      }

      const user = results[0];
      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(400).json({
          success: false,
          message: 'Credenciales incorrectas',
        });
      }

      // Crear el token JWT
      const token = jwt.sign(
        { userId: user.id, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );

      res.json({
        success: true,
        message: 'Inicio de sesión exitoso',
        token,
      });
    });

  } catch (err) {
    console.error('Error en el login:', err);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor',
    });
  }
});
