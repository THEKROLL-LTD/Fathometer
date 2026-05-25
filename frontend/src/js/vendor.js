import Alpine from "alpinejs";
import "htmx.org";
window.Alpine = Alpine;
// Alpine.start() laeuft in app.js NACH allen Alpine.data()-Registrierungen
// aus dem app-Bundle (server_detail.js u.a.). Wuerde es hier laufen, hat
// Alpine die DOM bereits gewalkt bevor app.js x-data-Komponenten registrieren
// kann -> 'serverPillPanels is not defined' o.ae.
