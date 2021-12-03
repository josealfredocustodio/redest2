import asyncio
from time import time
from tcputils import *
from random import randint

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

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora segmentos que não são destinados à porta do nosso servidor
            return
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao)
            
            # Gerando número de sequência aleatório e definindo ACK_NO
            conexao.seq_no = randint(0, 0xffff)
            conexao.ack_no = seq_no + 1

            # Criando flags
            flags = flags & 0
            flags = flags | (FLAGS_SYN | FLAGS_ACK)

            # Invertento endereço de origem e de destino
            src_port, dst_port = dst_port, src_port
            src_addr, dst_addr = dst_addr, src_addr

            # Construindo cabeçalho com flags SYN e ACK
            segmento = make_header(src_port, dst_port, conexao.seq_no, conexao.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)
            self.rede.enviar(segmento_checksum_corrigido, dst_addr)

            # Incrementando seq_no para considerar o SYN enviado
            conexao.seq_no += 1
            conexao.seq_no_base = conexao.seq_no

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
            print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))

    def _fechar_conexao(self, id_conexao):
        if id_conexao in self.conexoes:
            del self.conexoes[id_conexao]

class Conexao:
    def __init__(self, servidor, id_conexao):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.seq_no = None
        self.ack_no = None
        self.callback = None
        self.timer = None
        self.seq_no_base = None
        self.pacotes_sem_ack = []
        self.timeoutInterval = 1
        self.devRTT = None
        self.estimatedRTT = None
        self.fila_envio = []

    def _timer(self):
        if self.pacotes_sem_ack:
            segmento, _, dst_addr, _ = self.pacotes_sem_ack[0]
            # Reenviando pacote
            self.servidor.rede.enviar(segmento, dst_addr)
            self.pacotes_sem_ack[0][3] = None

    def _atualizar_timeout_interval(self):
        _, _, _, sampleRTT = self.pacotes_sem_ack[0]
        if sampleRTT is None:
            return

        sampleRTT = round(time(), 5) - sampleRTT
        if self.estimatedRTT is None:
            self.estimatedRTT = sampleRTT
            self.devRTT = sampleRTT/2
        else:
            self.estimatedRTT = 0.875*self.estimatedRTT + 0.125*sampleRTT
            self.devRTT = 0.75*self.devRTT + 0.25 * abs(sampleRTT-self.estimatedRTT)

        self.timeoutInterval = self.estimatedRTT + 4*self.devRTT

    def _rdt_rcv(self, seq_no, ack_no, flags, payload):
        print('recebido payload: %r' % payload)

        # Verificando se o pacote não é duplicado ou está fora de ordem
        if seq_no != self.ack_no:
            return

        # Se for um ACK, é preciso encerrar o timer e remover da lista de pacotes
        # que precisam ser confirmados
        if (flags & FLAGS_ACK) == FLAGS_ACK and ack_no > self.seq_no_base:
            self.seq_no_base = ack_no
            if self.pacotes_sem_ack:
                self._atualizar_timeout_interval()
                self.timer.cancel()
                self.pacotes_sem_ack.pop(0)
                if self.pacotes_sem_ack:
                    self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)

        # Se for um pedido de encerrar a conexão
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            payload = b''
            self.ack_no += 1
        elif len(payload) <= 0:
            return

        self.callback(self, payload)
        self.ack_no += len(payload)

        # Construindo e enviando pacote ACK
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        segmento = make_header(src_port, dst_port, self.seq_no_base, self.ack_no, FLAGS_ACK)
        segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)

        self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)


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
        # Construindo e enviando pacotes
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        flags = 0 | FLAGS_ACK

        for i in range( int(len(dados)/MSS) ):
            ini = i*MSS
            fim = min(len(dados), (i+1)*MSS)

            payload = dados[ini:fim]

            segmento = make_header(src_port, dst_port, self.seq_no, self.ack_no, flags)
            segmento_checksum_corrigido = fix_checksum(segmento+payload, src_addr, dst_addr)
            self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)

            self.timer = asyncio.get_event_loop().call_later(self.timeoutInterval, self._timer)
            self.pacotes_sem_ack.append( [segmento_checksum_corrigido, len(payload), dst_addr, round(time(), 5)] )

            # Atualizando seq_no com os dados recém enviados
            self.seq_no += len(payload)

    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        # Construindo e enviando pacote FYN
        dst_addr, dst_port, src_addr, src_port = self.id_conexao

        segmento = make_header(src_port, dst_port, self.seq_no, self.ack_no, FLAGS_FIN)
        segmento_checksum_corrigido = fix_checksum(segmento, src_addr, dst_addr)

        self.servidor.rede.enviar(segmento_checksum_corrigido, dst_addr)
        self.servidor._fechar_conexao(self.id_conexao)
