#ifndef REGISTRO_H
#define REGISTRO_H

#include <string>
#include <vector>
#include "Analisis.h"  // Para AnalisisPuerto

// =====================
// Módulo de registro en TXT
// =====================
class Registro {
public:
    // Guarda todos los resultados en un archivo TXT bien formateado
    static void guardarReporteTXT(
        const std::vector<AnalisisPuerto>& resultados,
        const std::string& nombreArchivo,
        const std::string& ip,
        const std::string& metodoEscaneo
    );
    
private:
    // Helper functions
    static std::string obtenerFechaHora();
    static int contarPuertosAbiertos(const std::vector<AnalisisPuerto>& resultados);
};

#endif // REGISTRO_H