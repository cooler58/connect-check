# Vendored UI

- `nuklear.h`, `nuklear_glfw_gl2.h` — [Nuklear](https://github.com/Immediate-Mode-UI/Nuklear) (public domain)
- `nuklear_gdip.h` — Windows GUI backend (GDI+, без OpenGL)
- `nuklear_glfw_gl2.h` — macOS/Linux GUI backend (GLFW/OpenGL2)
- `win/` — GLFW 3.4 MinGW-w64 для кросс-сборки `connect-check-gui.exe`

Шрифты GUI — **системные** (Segoe UI / Arial / DejaVu из пакетов ОС); в репозиторий и релиз не кладём.

macOS/Linux GLFW — системный (`brew install glfw` / `libglfw3-dev`); при сборке Linux `libglfw.so` копируется рядом с бинарём.
