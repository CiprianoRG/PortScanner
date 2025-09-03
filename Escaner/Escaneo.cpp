#include "Escaneo.h"
#include <iostream>
#include <cstring>      // memset
#include <chrono>

// =====================
// Dependiendo del sistema operativo incluimos librerías distintas
// =====================
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib") // librería de sockets en Windows
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

// =====================
// Función auxiliar para identificar el servicio por puerto
// =====================
std::string obtenerServicio(int puerto) {
    switch (puerto) {
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 443: return "HTTPS";
        case 3389: return "RDP";
        default: return "Desconocido";
    }
}

// =====================
// Función principal de escaneo de puertos
// =====================
std::vector<PortInfo> escanearPuertos(
    const std::string& ip,
    const std::vector<int>& puertos,
    int timeoutMs
) {
    std::vector<PortInfo> resultados;

#ifdef _WIN32
    // Inicializar la librería Winsock en Windows
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        std::cerr << "Error al iniciar Winsock.\n";
        return resultados;
    }
#endif

    // Recorremos cada puerto de la lista
    for (int puerto : puertos) {
        PortInfo info;
        info.port = puerto;
        info.proto = "TCP";
        info.servicio = obtenerServicio(puerto);
        info.sospechoso = false;
        info.razon = "";

        // Crear el socket TCP
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            info.estado = "ErrorSocket";
            resultados.push_back(info);
            continue;
        }

        // Configurar la dirección del servidor (IP + puerto)
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(puerto);

#ifdef _WIN32
        // En MinGW/Windows inet_pton no siempre está disponible
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            info.estado = "ErrorIP";
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            resultados.push_back(info);
            continue;
        }
#else
        // En Linux/macOS sí funciona inet_pton
        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
#ifdef _WIN32
            closesocket(sockfd);
#else
            close(sockfd);
#endif
            info.estado = "ErrorIP";
            resultados.push_back(info);
            continue;
        }
#endif

        // Poner el socket en modo "no bloqueante"
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sockfd, FIONBIO, &mode);
#else
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
#endif

        // Intentar conectar
        int res = connect(sockfd, (sockaddr*)&addr, sizeof(addr));
        if (res < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
                info.estado = "Cerrado";
                closesocket(sockfd);
                resultados.push_back(info);
                continue;
            }
#else
            if (errno != EINPROGRESS) {
                info.estado = "Cerrado";
                close(sockfd);
                resultados.push_back(info);
                continue;
            }
#endif
        }

        // Preparar conjunto de sockets para esperar con timeout
        fd_set set;
        FD_ZERO(&set);
        FD_SET(sockfd, &set);

        timeval timeout;
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = (timeoutMs % 1000) * 1000;

        res = select(sockfd + 1, nullptr, &set, nullptr, &timeout);
        if (res > 0) {
            int err;
            socklen_t len = sizeof(err);
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
            if (err == 0) {
                info.estado = "Abierto";
            } else {
                info.estado = "Cerrado";
            }
        } else if (res == 0) {
            info.estado = "Filtrado"; // timeout
        } else {
            info.estado = "Error";
        }

#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif

        resultados.push_back(info);
    }

#ifdef _WIN32
    WSACleanup();
#endif

    return resultados;
}
