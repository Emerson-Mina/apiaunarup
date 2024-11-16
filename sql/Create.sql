-- Crea una base de datos llamada 'miapp'
CREATE DATABASE miapp;

-- Selecciona la base de datos 'miapp' para usarla en las siguientes operaciones
USE miapp;

-- Crea una tabla llamada 'roles' para almacenar los roles de los usuarios
CREATE TABLE roles (
  id INT AUTO_INCREMENT PRIMARY KEY, -- 'id' es la clave primaria y se incrementa automáticamente
  name VARCHAR(255) UNIQUE NOT NULL  -- 'name' es el nombre del rol, debe ser único y no puede estar vacío
);

-- Inserta un rol con el nombre 'admin' en la tabla 'roles'
INSERT INTO roles (name) VALUES ('admin');

-- Inserta un rol con el nombre 'user' en la tabla 'roles'
INSERT INTO roles (name) VALUES ('user');

-- Crea una tabla llamada 'users' para almacenar la información de los usuarios
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY, -- 'id' es la clave primaria de la tabla y se incrementa automáticamente
  username VARCHAR(255) UNIQUE NOT NULL, -- 'username' debe ser único y no puede estar vacío
  password VARCHAR(255) NOT NULL, -- 'password' es la contraseña del usuario y es obligatoria
  role_id INT, -- 'role_id' es un campo que hace referencia al rol asignado al usuario

  -- Define 'role_id' como una clave externa que hace referencia a la columna 'id' de la tabla 'roles'
  -- 'ON DELETE SET NULL' significa que si se elimina un rol, 'role_id' se establece en NULL en la tabla 'users'
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL
);
