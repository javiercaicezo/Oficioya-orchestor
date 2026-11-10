# OficioYaOrchestor

links:

diagrama de clases: https://drive.google.com/file/d/1IVi8pvH5cWLwDkcuaqaRjFel-94Ye7Gf/view?usp=sharing

mockup:https://www.figma.com/design/NvDN2mIs8itoVR14fFOCbU/Flujo-Registro?node-id=0-1&t=Xj3LS6Kx0zLUyBub-1

diagrama de contenedores: https://drive.google.com/file/d/19WIlKDQu-FZlrHCcUTviBBt9I6yarxVt/view?usp=sharing

diagrama er: https://drive.google.com/file/d/1_6IEGdz9Dds-OPQab_qJLSVuQvPBjM_e/view?usp=sharing

## Cómo correr el proyecto en local

Requiere Java 21 y Docker.

1. Base de datos (desde la carpeta `OficioYa/`): `docker compose up -d`
2. Arrancar con el perfil `local`, que usa usuarios y notificaciones simulados en memoria:

   Windows (PowerShell): `.\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=local"`

   Linux / macOS: `./mvnw spring-boot:run -Dspring-boot.run.profiles=local`

El perfil `local` ya no se activa por defecto y trae su propio secreto JWT de desarrollo
(`application-local.yml`). En cualquier otro ambiente es obligatorio definir `JWT_SECRET` (en Base64,
mínimo 32 bytes); sin él la app no arranca. También se definen `DB_URL`, `DB_USER` y `DB_PASSWORD`.

Usuarios de prueba (solo perfil `local`): `carlos@oficioya.com` (CLIENT) y `admin@oficioya.com`
(ADMINISTRATOR). Sus contraseñas están en `DevDataSeeder`. Al arrancar se borran las credenciales
anteriores, porque los usuarios viven en memoria y sus ids reinician en cada arranque.
