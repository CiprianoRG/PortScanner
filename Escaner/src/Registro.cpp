#include "Registro.h"
#include <fstream>
#include <iostream>
#include <ctime>

// =====================
// Guardar resultados en archivo
// =====================
void guardarRegistro(const std::string& archivo,
                     const std::string& ip,
                     const std::vector<AnalisisPuerto>& analisis) {
    std::ofstream out(archivo, std::ios::app); // "app" = agregar al final
    if (!out.is_open()) {
        std::cerr << "No se pudo abrir " << archivo << " para guardar resultados.\n";
        return;
    }

    // Agregar encabezado con fecha/hora
    std::time_t ahora = std::time(nullptr);
    out << "\n==============================\n";
    out << "Resultados del escaneo - " << std::ctime(&ahora);
    out << "IP escaneada: " << ip << "\n\n";

    // Guardar resultados
    for (const auto& a : analisis) {
        out << "Puerto " << a.info.port << " (" << a.info.servicio << "): "
            << a.info.estado;

        if (a.info.estado == "Abierto") {
            out << " | Riesgo: " << obtenerDescripcionRiesgo(a.nivel_riesgo);
            out << " (" << a.puntuacion_riesgo << "/100)";
        }

        if (a.info.sospechoso) {
            out << " [Sospechoso: " << a.info.razon << "]";
        }

        out << "\n";

        for (const auto& vuln : a.vulnerabilidades) {
            out << "   - " << vuln << "\n";
        }
    }

    out << "==============================\n";
    out.close();

    std::cout << "\n[✔] Resultados guardados en '" << archivo << "'\n";
}
