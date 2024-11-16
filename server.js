// Requerimos las dependencias necesarias
require('dotenv').config(); // Carga las variables de entorno desde el archivo .env
const express = require('express'); // Framework web para crear el servidor
const mysql = require('mysql2'); // Paquete para interactuar con MySQL
const bcrypt = require('bcryptjs'); // Para encriptar y comparar contraseñas
const jwt = require('jsonwebtoken'); // Para crear y verificar tokens JWT

// Crear una instancia de la aplicación express
const app = express();
app.use(express.json()); // Middleware para parsear el cuerpo de las solicitudes en formato JSON

// Configuración de la conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST, // Dirección del host de la base de datos
  user: process.env.DB_USER, // Usuario de la base de datos
  password: process.env.DB_PASSWORD, // Contraseña de la base de datos
  database: process.env.DB_NAME, // Nombre de la base de datos
});

// Intentar conectar a la base de datos
db.connect(err => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err.message); // Si ocurre un error, lo mostramos
    process.exit(1); // Termina el proceso si la conexión falla
  } else {
    console.log('Conectado a la base de datos MySQL'); // Mensaje de éxito si la conexión es exitosa
  }
});

// Middleware para verificar el token JWT en las solicitudes
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Extraemos el token del encabezado Authorization

  if (!token) { // Si no hay token, devolvemos un error de acceso denegado
    return res.status(401).json({
      success: false,
      message: 'Acceso denegado: se requiere autenticación',
    });
  }

  // Verificamos que el token sea válido utilizando la clave secreta
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) { // Si el token no es válido o ha expirado
      return res.status(403).json({
        success: false,
        message: 'Token no válido o expirado',
      });
    }
    req.user = decoded; // Decodificamos el token y guardamos la información del usuario en el objeto req
    next(); // Continuamos al siguiente middleware o ruta
  });
};

// Middleware para verificar si el usuario tiene rol de administrador
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') { // Si el rol del usuario no es 'admin'
    return res.status(403).json({
      success: false,
      message: 'Acceso denegado: solo los administradores pueden acceder a esta ruta',
    });
  }
  next(); // Si es admin, continuamos al siguiente middleware o ruta
};

// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body; // Extraemos los datos del cuerpo de la solicitud

  const queryRole = 'SELECT id FROM roles WHERE name = ?'; // Consulta SQL para verificar si el rol existe en la base de datos
  db.query(queryRole, [role], async (err, result) => { // Ejecutamos la consulta
    if (err) { // Si hay un error con la consulta
      console.error('Error al verificar rol:', err.message);
      return res.status(500).json({
        success: false,
        message: 'Error interno al registrar el usuario',
      });
    }

    if (result.length === 0) { // Si no encontramos el rol en la base de datos
      return res.status(400).json({
        success: false,
        message: 'Rol no válido. Debe ser "admin" o "user".',
      });
    }

    // Si el rol es válido, encriptamos la contraseña antes de guardarla
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)'; // Consulta para insertar el usuario en la base de datos
    db.query(query, [username, hashedPassword, result[0].id], (err) => { // Ejecutamos la consulta
      if (err) { // Si hay un error al registrar el usuario
        console.error('Error al registrar el usuario:', err.message);
        return res.status(500).json({
          success: false,
          message: 'Error al registrar el usuario. El nombre de usuario podría estar en uso.',
        });
      }
      // Si todo es correcto, enviamos una respuesta de éxito
      res.status(201).json({
        success: true,
        message: `Usuario ${username} registrado exitosamente.`,
      });
    });
  });
});

// Ruta para iniciar sesión de usuario
app.post('/login', (req, res) => {
  const { username, password } = req.body; // Extraemos los datos del cuerpo de la solicitud

  const query = 'SELECT u.id, u.username, u.password, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.username = ?'; // Consulta para verificar las credenciales
  db.query(query, [username], async (err, results) => { // Ejecutamos la consulta
    if (err) { // Si ocurre un error al realizar la consulta
      console.error('Error al verificar usuario:', err.message);
      return res.status(500).json({
        success: false,
        message: 'Error interno al iniciar sesión',
      });
    }

    if (results.length === 0) { // Si no encontramos al usuario en la base de datos
      return res.status(404).json({
        success: false,
        message: 'Credenciales incorrectas',
      });
    }

    const user = results[0]; // Si el usuario existe, tomamos la primera coincidencia
    const validPassword = await bcrypt.compare(password, user.password); // Comparamos la contraseña ingresada con la guardada en la base de datos

    if (!validPassword) { // Si las contraseñas no coinciden
      return res.status(400).json({
        success: false,
        message: 'Credenciales incorrectas',
      });
    }

    // Si las credenciales son válidas, generamos un token JWT con la información del usuario
    const token = jwt.sign(
      { userId: user.id, role: user.role }, // Creamos el payload con la ID del usuario y su rol
      process.env.JWT_SECRET, // Usamos la clave secreta definida en el archivo .env
      { expiresIn: '1h' } // Establecemos el tiempo de expiración del token
    );

    res.json({
      success: true,
      message: 'Inicio de sesión exitoso',
      token, // Devolvemos el token generado
    });
  });
});

// Ruta para obtener el perfil de un usuario autenticado
app.get('/profile', verifyToken, (req, res) => {
  res.json({
    success: true,
    message: `Bienvenido, usuario ID: ${req.user.userId}`, // Usamos la información del usuario decodificada en el token
    userRole: req.user.role, // Mostramos el rol del usuario
  });
});

// Ruta para que el administrador restablezca la contraseña de un usuario
app.post('/reset-password', verifyToken, verifyAdmin, async (req, res) => {
  const { username, newPassword } = req.body; // Extraemos los datos del cuerpo de la solicitud

  if (!username || !newPassword) { // Verificamos que se proporcionen ambos parámetros
    return res.status(400).json({
      success: false,
      message: 'Por favor, proporciona el nombre de usuario y la nueva contraseña',
    });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10); // Encriptamos la nueva contraseña

  const query = 'UPDATE users SET password = ? WHERE username = ?'; // Consulta para actualizar la contraseña del usuario
  db.query(query, [hashedPassword, username], (err, result) => { // Ejecutamos la consulta
    if (err) { // Si ocurre un error
      console.error('Error al restablecer la contraseña:', err.message);
      return res.status(500).json({
        success: false,
        message: 'Error interno al restablecer la contraseña',
      });
    }

    if (result.affectedRows === 0) { // Si no se encontró el usuario en la base de datos
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado',
      });
    }

    // Si la contraseña fue actualizada correctamente
    res.status(200).json({
      success: true,
      message: `La contraseña de ${username} se ha restablecido correctamente`,
    });
  });
});

// Iniciar el servidor en el puerto 3000
app.listen(3000, () => {
  console.log('Servidor corriendo en el puerto 3000');
});
