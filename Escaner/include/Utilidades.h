#ifndef UTILIDADES_H
#define UTILIDADES_H

#include <string>
#include <vector>

// Valida dirección IPv4
bool validarIP(const std::string& ip);

// Pide al usuario una IP y un rango de puertos válidos
std::vector<int> pedirIPyPuertos(std::string& ip);

// Genera un vector con todos los puertos entre inicio y fin; No tiene utilidad porque es remplazada por el siguiente vector
std::vector<int> generarListaPuertos(int inicio, int fin);

// Convierte la entrada del usuario (ej. "20-25,80,443") en un vector<int>
std::vector<int> parsearPuertos(const std::string& entrada);

// Verifica si Nmap está instalado (y lo instala si es posible)
void verificarONstalarNmap();

// Devuelve un nombre de servicio común para un puerto
std::string servicioPorPuerto(int puerto);

#endif // UTILIDADES_H
