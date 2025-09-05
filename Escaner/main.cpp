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
//#include "Registro.h"     // si quieres guardar los resultados

int main() {
    std::string ip;

    // 1. Pedir IP y lista de puertos (puede ser rango, lista o mezcla)
    std::vector<int> puertos = pedirIPyPuertos(ip);

    // 2. Elegir estrategia de escaneo
    int opcion;
    std::cout << "\nElige estrategia de escaneo:\n";
    std::cout << "1) Sockets clásicos\n";
    std::cout << "2) ASIO (asíncrono)\n";
    std::cout << "3) Nmap (externo)\n";
    std::cout << "Opción: ";
    std::cin >> opcion;

    std::unique_ptr<EstrategiaEscaneo> estrategia;

    if (opcion == 1) {
        estrategia = std::make_unique<EscaneoSockets>();
    } else if (opcion == 2) {
        estrategia = std::make_unique<EscaneoAsio>();
    } else if (opcion == 3) {
        verificarONstalarNmap(); // del módulo Utilidades
        estrategia = std::make_unique<EscaneoNmap>();
    } else {
        std::cerr << "Opción inválida.\n";
        return 1;
    }

    // 3. Ejecutar escaneo
    std::cout << "\n[*] Escaneando " << ip << "...\n";
    std::vector<PortInfo> resultados = estrategia->escanear(ip, puertos);

    // 4. Analizar resultados
    analizarPuertosSospechosos(resultados, MEDIO);

    // 5. Mostrar resumen en terminal
    std::cout << "\n--- Resultados del escaneo ---\n";
    for (const auto& r : resultados) {
        std::cout << "Puerto " << r.port << " (" << r.servicio << "): "
                  << r.estado;
        if (r.sospechoso) {
            std::cout << " [Sospechoso: " << r.razon << "]";
        }
        std::cout << "\n";
    }

    // 6. (Opcional) Guardar en archivo
   // guardarRegistro(resultados, "Registro.txt", ip);

    std::cout << "\n[✔] Resultados guardados en 'Registro.txt'\n";

    return 0;
}
