import asyncio
import random
import math
import time

#from loguru import logger
import logging as logger

from tcputils import (
    FLAGS_FIN,
    FLAGS_SYN,
    FLAGS_ACK,
    MSS,
    make_header,
    read_header,
    fix_checksum,
    calc_checksum,
)


class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def open_connection(self, id_conexao, segment):
        _, _, seq_no, _, flags, _, _, _ = read_header(segment)
        src_addr, src_port, dst_addr, dst_port = id_conexao

        ack_no = seq_no + 1
        seq_no = random.randint(10, 0xFFFF)

        ack_segment = make_header(dst_port, src_port, seq_no, ack_no, FLAGS_SYN | FLAGS_ACK)
        ack_segment = fix_checksum(ack_segment, src_addr, dst_addr)
        self.rede.enviar(ack_segment, src_addr)
        logger.info(
            f"Nova conexão: {id_conexao}, handshake enviado: (seq_no: {seq_no} ack_no: {ack_no})"
        )
        return Conexao(self, id_conexao, seq_no + 1, ack_no)

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, flags, _, checksum, _ = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return

        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            logger.warning("Checksum inválida, ignorando pacote!")
            return

        payload = segment[4 * (flags >> 12) :]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = self.open_connection(id_conexao, segment)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            logger.warning(
                f"{src_addr}:{src_port} -> {dst_addr}:{dst_port} (pacote associado à conexão desconhecida)"
            )


class Conexao:
    def __init__(self, servidor, id_conexao, seq_no, ack_no):
        self.servidor = servidor
        # id_conexao = (src_addr, src_port, dst_addr, dst_port)
        self.id_conexao = id_conexao
        self.callback = None
        self.timer = None

        self.send_base = seq_no
        self.last_seq = seq_no
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.bytes_acked = 0

        self.unacked = b""
        self.unsent = b""
        self.timeout_interval = 0.5
        self.begin_time = None
        self.end_time = None
        self.sample_rtt = None
        self.estimated_rtt = None
        self.dev_rtt = None
        self.first_iteration = True

        self.window = 1
        self.closing = False
        self.retransmitting = False

    def _timeout(self):
        logger.warning(f"Timeout na conexão {self.id_conexao}")
        self.timer = None
        self.window = max(self.window // 2, 1)
        logger.debug(f"O window size atual é {self.window} MSS.")
        self._retransmit()
        self._start_timer()

    def _start_timer(self):
        if self.timer:
            self._stop_timer()
        self.timer = asyncio.get_event_loop().call_later(self.timeout_interval, self._timeout)
        logger.debug("O timer iniciado.")

    def _stop_timer(self):
        self.timer.cancel()
        self.timer = None
        logger.debug("O timer foi parado.")

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        if self.ack_no != seq_no:
            return

        if (flags & FLAGS_FIN) == FLAGS_FIN and not self.closing:
            # Cliente enviou um FIN, responde com ACK e espera confirmação
            self.closing = True
            self.callback(self, b"")
            self.ack_no += 1
            self._send_ack_segment(b"")
        elif (flags & FLAGS_ACK) == FLAGS_ACK and self.closing:
            # Cliente confirmou o fechamento, fecha a conexão
            logger.critical(f"Terminando conexão {self.id_conexao}")
            del self.servidor.conexoes[self.id_conexao]
            return

        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.send_base:
            logger.info(f"Esperando ACK em {len(self.unacked)} bytes.")
            self.unacked = self.unacked[ack_no - self.send_base :]
            logger.info(f"{ack_no - self.send_base} bytes receberam o ACK.")
            self.bytes_acked = ack_no - self.send_base
            self.send_base = ack_no

            if self.unacked:
                self._start_timer()
            else:
                if self.timer:
                    self._stop_timer()
                if not self.retransmitting:
                    self.end_time = time.time()
                    logger.debug(f"Momento do fim da transação: {self.end_time}")
                    self._calc_rtt()
                else:
                    self.retransmitting = False

        if self.bytes_acked >= MSS:
            # Se MSS ou mais bytes receberam ACK, aumenta o tamanho da janela
            self.bytes_acked -= MSS
            self.window += 1
            logger.debug(f"O window size atual é {self.window} MSS.")
            self._send_pending()

        if payload:
            self.ack_no += len(payload)
            self.callback(self, payload)
            header = fix_checksum(
                make_header(
                    self.id_conexao[1], self.id_conexao[3], self.seq_no, self.ack_no, flags
                ),
                self.id_conexao[0],
                self.id_conexao[2],
            )
            self.servidor.rede.enviar(header, self.id_conexao[2])
            if not self.timer:
                self._start_timer()

    def _retransmit(self):
        logger.info("Começando retransmissão...")
        self.retransmitting = True
        # Retransmite apenas o segmento mais antigo
        length = min(MSS, len(self.unacked))
        data = self.unacked[:length]
        self._send_ack_segment(data)

    def _send_ack_segment(self, data):
        seq_no = None
        if self.retransmitting:
            seq_no = self.send_base
        else:
            seq_no = self.seq_no
            self.seq_no += len(data)
            self.unacked += data
            self.begin_time = time.time()
            logger.debug(f"Momento do começo da transação: {self.begin_time}")

        header = make_header(self.id_conexao[1], self.id_conexao[3], seq_no, self.ack_no, FLAGS_ACK)
        ack_segment = fix_checksum(header + data, self.id_conexao[0], self.id_conexao[2])
        self.servidor.rede.enviar(ack_segment, self.id_conexao[2])

        if not self.timer and not self.closing:
            self._start_timer()

    def _send_pending(self):
        size_pending = (self.window * MSS) - len(self.unacked)

        if size_pending > 0:
            ready_to_send = self.unsent[:size_pending]
            if len(ready_to_send) == 0:
                return
            self.unsent = self.unsent[size_pending:]
            self.last_seq = self.seq_no + len(ready_to_send)

            n_segment = math.ceil(len(ready_to_send) / MSS)
            if n_segment == 0:
                n_segment = 1
            for i in range(n_segment):
                segment = ready_to_send[i * MSS : (i + 1) * MSS]
                self._send_ack_segment(segment)

    def _calc_rtt(self):
        alfa = 0.125
        beta = 0.25

        self.sample_rtt = self.end_time - self.begin_time

        if self.first_iteration:
            self.first_iteration = False

            self.estimated_rtt = self.sample_rtt
            self.dev_rtt = self.sample_rtt / 2
        else:
            self.estimated_rtt = ((1 - alfa) * self.estimated_rtt) + (alfa * self.sample_rtt)
            self.dev_rtt = ((1 - beta) * self.dev_rtt) + (
                beta * abs(self.sample_rtt - self.estimated_rtt)
            )

        self.timeout_interval = self.estimated_rtt + (4 * self.dev_rtt)
        logger.info(f"RTT atualizado para {self.timeout_interval:0.3}s.")

    # Os métodos abaixo fazem parte da API
    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        self.unsent += dados
        ready_to_send = self.unsent[: (self.window * MSS)]
        self.unsent = self.unsent[(self.window * MSS) :]

        self.last_seq = self.seq_no + len(ready_to_send)
        n_segment = math.ceil(len(ready_to_send) / MSS)

        if n_segment == 0:
            n_segment = 1
        for i in range(n_segment):
            segment = ready_to_send[i * MSS : (i + 1) * MSS]
            self._send_ack_segment(segment)

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """

        ack_segment = make_header(
            self.id_conexao[3], self.id_conexao[1], self.seq_no, self.ack_no, FLAGS_FIN
        )
        self.servidor.rede.enviar(
            fix_checksum(ack_segment, self.id_conexao[2], self.id_conexao[0]), self.id_conexao[0]
        )
