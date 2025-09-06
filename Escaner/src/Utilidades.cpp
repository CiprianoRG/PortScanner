#include "Utilidades.h"
#include <iostream>
#include <sstream>
#include <cctype>
#include <cstdlib>
#include <set>


bool validarIP(const std::string& ip) {
    std::stringstream ss(ip);
    std::string segmento;
    std::vector<std::string> partes;

    while (getline(ss, segmento, '.')) {
        partes.push_back(segmento);
    }

    if (partes.size() != 4) return false;

    for (const std::string& parte : partes) {
        if (parte.empty()) return false;
        for (char c : parte) {
            if (!isdigit(c)) return false;
        }
        int num = stoi(parte);
        if (num < 0 || num > 255) return false;
        if (parte.size() > 1 && parte[0] == '0') return false;
    }
    return true;
}

std::vector<int> pedirIPyPuertos(std::string& ip) {//funcion que almacena los valores de la ip y los puertos
    while (true) {
        std::cout << "Ingresa la direccion IP: ";
        std::cin >> ip;
        if (validarIP(ip)) break;
        std::cout << "IP invalida, intenta de nuevo.\n";
    }

    std::string entradaPuertos;
    std::cout << "Ingresa puertos (ej. 20-25,80,443): ";
    std::cin >> entradaPuertos;

    return parsearPuertos(entradaPuertos); // 👈 aquí usas tu versión mejorada
}

//Esta funcion es la primera version de la siguiennte; parsearPuertos
std::vector<int> generarListaPuertos(int inicio, int fin) {
    std::vector<int> lista;
    for (int p = inicio; p <= fin; ++p) lista.push_back(p);
    return lista;
}

std::vector<int> parsearPuertos(const std::string& entrada) {
    std::set<int> puertosUnicos; // usamos set para evitar duplicados
    std::stringstream ss(entrada);
    std::string token;

    while (std::getline(ss, token, ',')) { 
        // Revisar si el token es un rango con '-'
        size_t pos = token.find('-');
        if (pos != std::string::npos) {
            int inicio = std::stoi(token.substr(0, pos));
            int fin = std::stoi(token.substr(pos + 1));
            if (inicio > fin) std::swap(inicio, fin); // corregir si está invertido
            for (int p = inicio; p <= fin; ++p) {
                if (p >= 1 && p <= 65535) puertosUnicos.insert(p);
            }
        } else {
            // Puerto individual
            int puerto = std::stoi(token);
            if (puerto >= 1 && puerto <= 65535) {
                puertosUnicos.insert(puerto);
            }
        }
    }

    // Convertir set ordenado a vector
    return std::vector<int>(puertosUnicos.begin(), puertosUnicos.end());
}

void verificarONstalarNmap() {
#ifdef _WIN32
    if (system("where nmap >nul 2>nul") != 0) {
        std::cout << "[*] Nmap no está instalado en Windows.\n";
        std::cout << "Por favor instale Nmap manualmente desde: https://nmap.org/download.html\n";
    } else {
        std::cout << "[✔] Nmap ya está instalado en Windows.\n";
    }
#elif __linux__
    if (system("which nmap > /dev/null 2>&1") != 0) {
        std::cout << "[*] Nmap no está instalado en Linux.\n";
        std::cout << "Intente instalarlo con: sudo apt-get install nmap\n";
    } else {
        std::cout << "[✔] Nmap ya está instalado en Linux.\n";
    }
#elif __APPLE__
    if (system("which nmap > /dev/null 2>&1") != 0) {
        std::cout << "[*] Nmap no está instalado en macOS.\n";
        std::cout << "Intente instalarlo con: brew install nmap\n";
    } else {
        std::cout << "[✔] Nmap ya está instalado en macOS.\n";
    }
#endif
}

std::string servicioPorPuerto(int puerto) {
    switch (puerto) {
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        default: return "Desconocido";
    }
}
