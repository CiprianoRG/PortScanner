#include "EscaneoNmap.h"
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iostream>

// Implementación de escaneo con Nmap
std::vector<PortInfo> EscaneoNmap::escanear(
    const std::string& ip,
    const std::vector<int>& puertos,
    int timeoutMs
) {
    std::vector<PortInfo> resultados;

    if (puertos.empty()) {
        std::cerr << "No se especificaron puertos para escanear.\n";
        return resultados;
    }

    // Construir rango de puertos como string
    int inicio = puertos.front();
    int fin = puertos.back();
    std::string rango = std::to_string(inicio) + "-" + std::to_string(fin);

    // Ejecutar Nmap y guardar salida en archivo temporal
    std::string archivo = "Registro.txt";
    std::string comando = "nmap -p " + rango + " " + ip + " > " + archivo;
    system(comando.c_str());

    // Leer salida de Nmap
    std::ifstream in(archivo);
    if (!in.is_open()) {
        std::cerr << "No se pudo abrir " << archivo << " para análisis\n";
        return resultados;
    }

    std::string linea;
    while (std::getline(in, linea)) {
        if (linea.find("/tcp") != std::string::npos) {
            std::stringstream ss(linea);

            int puerto;
            std::string proto_estado, estado, servicio;
            ss >> puerto >> proto_estado >> estado >> servicio;

            PortInfo info;
            info.port = puerto;
            info.proto = "TCP";
            info.estado = (estado == "open") ? "Abierto" : "Cerrado";
            info.servicio = servicio;
            info.sospechoso = false;
            info.razon = "";

            resultados.push_back(info);
        }
    }

    in.close();
    return resultados;
}
