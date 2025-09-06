#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>

// Estructura que guarda la información de un puerto
// =====================
struct PortInfo {
    int port;                 // número de puerto
    std::string proto;        // protocolo (ej. "TCP")
    std::string estado;       // "Abierto", "Cerrado", "Filtrado", etc.
    std::string servicio;     // servicio conocido (HTTP, SSH, etc.)
    bool sospechoso;          // para marcarlo después en el análisis
    std::string razon;        // explicación si es sospechoso
};

#endif
