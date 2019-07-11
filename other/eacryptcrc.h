/*
EA Games CRC and packets encryption 0.1
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org

INTRODUCTION
============
Functions for encrypting/decrypting and calculating the CRC of the
packets used in the games developed by Electronic Arts like
The Lord of the Rings: the Battle for Middle-Earth II, 
Command & Conquer 3, Red Alert 3 and so on.

EXAMPLE
=======
decrypt:
  ea_crypt(packet, packet_len, 0);
  crc = ea_crc(packet + 4, packet_len - 4);

encrypt:
  *(unsigned int *)packet = ea_crc(packet + 4, packet_len - 4);
  ea_crypt(packet, packet_len, 1);

LICENSE
=======
    Copyright 2009 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

unsigned int ea_crc(unsigned char *data, int datalen) {
    unsigned int    crc;
    int             i;

    crc = 0;
    for(i = 0; i < datalen; i++) {
        crc = (crc >> 31) + (crc << 1) + data[i];
    }
    return(crc);
}



void ea_crypt(unsigned char *data, int datalen, int encrypt) {
    unsigned int    n,
                    *p;
    int             i;

    n = 0x38d9b7d4;
    p = (unsigned int *)data;
    datalen /= 4;
    for(i = 0; i < datalen; i++) {
        if(encrypt) {
            p[i] = ntohl(p[i] ^ n);
        } else {
            p[i] = ntohl(p[i]) ^ n;
        }
        n -= 0x7f39c50e;
    }
}


