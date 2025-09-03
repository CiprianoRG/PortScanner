#include <iostream>
#include <vector>
#include "Escaneo.h"
#include "Analisis.h"  // <- Nuevo include

int main() {
    std::string ip = "127.0.0.1";
    std::vector<int> puertos = {22, 80, 443, 4444, 3389, 31337, 10001};
    int timeout = 500;

    std::cout << "Escaneando " << ip << "...\n";
    std::vector<PortInfo> resultados = escanearPuertos(ip, puertos, timeout);

    // =====================
    // NUEVO: ANÁLISIS DE PUERTOS SOSPECHOSOS
    // =====================
    NivelSensibilidad sensibilidad = MEDIO;  // Puede ser BAJO, MEDIO o ALTO
    analizarPuertosSospechosos(resultados, sensibilidad);

    // =====================
    // MOSTRAR RESULTADOS MEJORADOS
    // =====================
    std::cout << "\n=== RESULTADOS DEL ESCANEO ===" << std::endl;
    for (const auto& r : resultados) {
        std::cout << "Puerto " << r.port << " (" << r.servicio << "): " << r.estado;
        
        if (r.sospechoso) {
            std::cout << " \033[1;31m[SOSPECHOSO]\033[0m - " << r.razon;
        }
        
        std::cout << std::endl;
    }

    return 0;
}