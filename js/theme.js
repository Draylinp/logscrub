// LogScrub · tema e idioma iniciales
// Se carga en <head> para aplicar el tema guardado antes de pintar la página
// y evitar el parpadeo de claro a oscuro.
(function () {
  "use strict";
  const root = document.documentElement;
  try {
    const theme = localStorage.getItem("logscrub.theme");
    if (theme === "light" || theme === "dark") root.dataset.theme = theme;
  } catch {
    // almacenamiento bloqueado: se usa el tema del sistema
  }
})();
