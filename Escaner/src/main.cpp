#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include "EstrategiaEscaneo.h"
#include "EscaneoSockets.h"
#include "EscaneoAsio.h"
#include "EscaneoNmap.h"
#include "Analisis.h"
#include "Utilidades.h"   // pedirIPyRango, validar IP, etc.
#include "Registro.h"     // si quieres guardar los resultados

int main() {
    std::string ip;

    // 1. Pedir IP y lista de puertos (puede ser rango, lista o mezcla)
    std::vector<int> puertos = pedirIPyPuertos(ip);

    // 2. Elegir estrategia de escaneo
    int opcion;
    std::cout << "\nElige estrategia de escaneo:\n";
    std::cout << "1) Sockets clasicos\n";
    std::cout << "2) ASIO (asíncrono)\n";
    std::cout << "3) Nmap (externo)\n";
    std::cout << "Opcion: ";
    std::cin >> opcion;

    std::unique_ptr<EstrategiaEscaneo> estrategia;
    std::string metodoEscaneo;

    if (opcion == 1) {
        estrategia = std::make_unique<EscaneoSockets>();
        metodoEscaneo = "Sockets clasicos";
    } else if (opcion == 2) {
        estrategia = std::make_unique<EscaneoAsio>();
        metodoEscaneo = "ASIO (asíncrono)";
    } else if (opcion == 3) {
        verificarONstalarNmap(); // del módulo Utilidades
        estrategia = std::make_unique<EscaneoNmap>();
        metodoEscaneo = "Nmap (externo)";
    } else {
        std::cerr << "Opcion invalida.\n";
        return 1;
    }

    // 3. Ejecutar escaneo
    std::cout << "\n[*] Escaneando " << ip << "...\n";
    std::vector<PortInfo> resultados = estrategia->escanear(ip, puertos);

        // 🔹 Post-procesar resultados para rellenar servicios vacíos
    for (auto& r : resultados) {
        if (r.servicio.empty()) {
            r.servicio = servicioPorPuerto(r.port);
        }
    }
    std::cout << "[✔] Escaneo completado.\n";
    // 4. Analizar resultados
    auto analisis_detallado = analizarPuertosDetallado(resultados);

    // 5. Mostrar resumen en terminal
    std::cout << "\n--- Resultados del escaneo ---\n";
    for (size_t i = 0; i < resultados.size(); ++i) {
        const auto& r = resultados[i];
        const auto& analisis = analisis_detallado[i];

        std::cout << "Puerto " << r.port << " (" << r.servicio << "): "
                << r.estado;

        if (r.estado == "Abierto") {
            std::cout << " | Riesgo: " << obtenerDescripcionRiesgo(analisis.nivel_riesgo);
            // Opcional: mostrar puntuacion
            // std::cout << " (" << analisis.puntuacion_riesgo << "/100)";
        }

        if (r.sospechoso) {
            std::cout << " [Sospechoso: " << r.razon << "]";
        }

        std::cout << "\n";

        // Vulnerabilidades adicionales
        for (const auto& vuln : analisis.vulnerabilidades) {
            std::cout << "   - " << vuln << "\n";
        }
    }

    // 5. Mostrar resumen MUY simple en terminal
    std::cout << "\n--- RESULTADOS ---\n";
    std::cout << "IP: " << ip << " | Metodo: " << metodoEscaneo << "\n";
    std::cout << "Puertos escaneados: " << resultados.size() << "\n";

    int abiertos = 0;
    int sospechosos = 0;
    for (const auto& r : resultados) {
        if (r.estado == "Abierto") abiertos++;
        if (r.sospechoso) sospechosos++;
    }

    std::cout << "Puertos abiertos: " << abiertos << "\n";
    std::cout << "Puertos sospechosos: " << sospechosos << "\n\n";

    // Solo mostrar lista muy breve de puertos abiertos
    if (abiertos > 0) {
        std::cout << "Puertos abiertos encontrados:\n";
        for (size_t i = 0; i < resultados.size(); ++i) {
            const auto& r = resultados[i];
            if (r.estado == "Abierto") {
                std::cout << "- Puerto " << r.port << " (" << r.servicio << ")";
                if (r.sospechoso) std::cout << " [SOSPECHOSO]";
                std::cout << "\n";
            }
        }
    } else {
        std::cout << "No se encontraron puertos abiertos.\n";
    }



    // 6. (Opcional) Guardar en archivo
    // ip es la IP que escaneaste
    // metodoEscaneo es un string que describes tú, por ejemplo "ASIO" o "Sockets clásicos"
    Registro reg;
    reg.guardarReporteTXT(analisis_detallado, "Registro.txt", ip, metodoEscaneo);

    std::cout << "Reporte detallado  guardados en 'Registro.txt'\n";

    return 0;
}
