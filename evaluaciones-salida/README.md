# Sistema de Evaluaciones de Salida — FYRESA

Sistema web completo para control de evaluaciones de salida con clasificación A / B / C
y flujo de autorización multinivel en 3 niveles.

## Instalación rápida

Requisitos: Python 3.8+ y pip

```bash
cd backend
pip install flask flask-cors
python3 server.py
```

Accede en: http://localhost:3000

## Usuarios demo

| Email | Contraseña | Rol |
|-------|-----------|-----|
| admin@fyresa.com | fyresa2026 | Administrador |
| supervisor@fyresa.com | fyresa2026 | Supervisor |
| superintendente@fyresa.com | fyresa2026 | Superintendente |
| coord.construccion@fyresa.com | fyresa2026 | Coord. Construcción |
| coord.rrhh@fyresa.com | fyresa2026 | Coord. RRHH |

## Funcionalidades

- Gestión de evaluaciones de salida con clasificación A/B/C
- Flujo secuencial: Superintendente → Coord. Construcción → Coord. RRHH
- Reportes y estadísticas
- Criterios de clasificación editables
- Gestión de usuarios por rol
