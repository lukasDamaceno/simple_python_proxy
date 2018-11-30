#!/usr/bin/env python3
# -*- coding: utf-8 -*-


try:
    from existence import death as relief
except ImportError:
    pass

import argparse
import os
import socket
import atexit
import codecs
import logging

from scapy.all import *
from netfilterqueue import NetfilterQueue

DFT_IPT_RULE = 'iptables -I OUTPUT -j NFQUEUE --queue-num 1'

parser = argparse.ArgumentParser(description='Servidor proxy simples usando Scapy e NetfilterQueue.', usage='./%(prog)s [args]')
# parser.add_argument('-p', '--port', type=int, help='Porta que será escutada pelo socket do servidor proxy.', required=True)
parser.add_argument('-F', '--flush-output', help='Limpa todas as regras de OUTPUT chain nas iptables.', action='store_true')
parser.add_argument('-L', '--log-file', help='Arquivo para escrever as requisições (suprime mensagens na stdout).', required=False, default=False)
args = parser.parse_args()

class Proxy:
    def __init__(self, port=0, iptables=DFT_IPT_RULE):
        self.port = port
        self.iptables = iptables
        self.__setIptables()
        self.hexEncoder = codecs.getencoder('hex')

    def __setIptables(self):
        print('[*] Adicionando regra de iptable: {}'.format(self.iptables))
        os.system(self.iptables)

    def run(self):
        print('[*] Iniciando NFQueue...')
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.__inspectPacket)
        s = socket.fromfd(nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            print('[*] Iniciando socket...')
            nfqueue.run_socket(s)
        except Exception or KeyboardInterrupt:
            self.__flushOutput()
            self.__terminate()

    def __inspectPacket(self, packet):
               
        payload = packet.get_payload()
        pkt = IP(payload)
        # print('[*] Pacote recebido! Endereço do destinatário: ' + str(pkt.dport))
        try:
            logging.info("""
****************************** Pacote recebido! ******************************
##Endereço do remetente: {}
##HTTPS: {}
##Dados: 
{}
******************************************************************************
            """.format(pkt[IP].dst, 'Sim' if pkt[IP].dport == 443 else 'Não' if pkt[IP].dport == 80 else 'Não identificado', "\n".join(pkt.sprintf("{Raw:%Raw.load%}\n").split(r"\n\r"))))
        except AttributeError:
            pass
        packet.accept()

    @staticmethod
    def flushOutput(flush_all=False):
        cmd = 'iptables -' + ('D OUTPUT 1' if not flush_all else 'F OUTPUT')
        print('[*] Deletando regras de iptable criadas: {}'.format(cmd))
        os.system(cmd)

    @staticmethod
    def terminate():
        Proxy.flushOutput()
        print('[*] Encerrando...')
        quit()

def terminate():
    try:
        Proxy.terminate()
    except SystemExit:
        pass

atexit.register(terminate)

logging.basicConfig(filename=args.log_file or None, level=logging.NOTSET, format='%(message)s')

if __name__ == '__main__':
    
        
    if args.flush_output:
        Proxy.flushOutput(args.flush_output)
    proxy = Proxy()
    proxy.run()