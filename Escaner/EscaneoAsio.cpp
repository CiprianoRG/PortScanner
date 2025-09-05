#include "EscaneoAsio.h"
#include <iostream>
#include <memory>
#include <chrono>

using asio::ip::tcp;

std::vector<PortInfo> EscaneoAsio::escanear(
    const std::string& ip,
    const std::vector<int>& puertos,
    int timeoutMs
) {
    std::vector<PortInfo> resultados;
    asio::io_context io;

    for (int port : puertos) {
        auto sock  = std::make_shared<tcp::socket>(io);
        auto timer = std::make_shared<asio::steady_timer>(io);
        tcp::endpoint endpoint(asio::ip::make_address(ip), port);

        timer->expires_after(std::chrono::milliseconds(timeoutMs));
        timer->async_wait([sock](const asio::error_code&) {
            if (sock->is_open()) {
                sock->close();
            }
        });

        sock->async_connect(endpoint,
            [sock, port, timer, &resultados](const asio::error_code& ec) {
                PortInfo info;
                info.port = port;
                info.proto = "TCP";
                info.servicio = ""; // servicio desconocido (se puede mapear después)
                info.sospechoso = false;
                info.razon = "";
                
                if (!ec) {
                    info.estado = "Abierto";
                } else if (ec == asio::error::timed_out) {
                    info.estado = "Filtrado";
                } else {
                    info.estado = "Cerrado";
                }

                resultados.push_back(info);
                timer->cancel();
            }
        );
    }

    io.run();
    return resultados;
}
