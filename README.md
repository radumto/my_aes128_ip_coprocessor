# my_aes128_ip_coprocessor
This AES implementation is an asynchronous, combinational implementation in Verilog; the module implements the encryption algorithm and the key expansion algorithm; the ciphertext result is generated after the propagation delay through the AES rounds; the AES coprocessor was tested with the NIST example found in AES_NIST.FIPS.197.pdf
The references for this implementation are:
[1] NIST, AES_NIST.FIPS.197, November 2001; posted in the Appendix. 
[2] M. Mayhew, ASIC Implementation of an AES co-processor, MASc Thesis, 2009, University of Guelph (pp. 46 – 67; posted on ENGG*4560 CourseLink.  
[3] J. Wolkerstorfer, E. Oswald, M. Lamberger (2002). An ASIC Implementation of the AES SBoxes. In: Preneel, B. (eds) Topics in Cryptology — CT-RSA 2002. CT-RSA 2002. Lecture Notes in Computer Science, vol 2271. Springer, Berlin, Heidelberg. https://doi-org.subzero.lib.uoguelph.ca/10.1007/3-540-45760-7_6; posted in the Appendix.
[4] Hua Li and Z. Friggstad, "An efficient architecture for the AES mix columns operation," 2005 IEEE International Symposium on Circuits and Systems (ISCAS), 2005, pp. 4637-4640 Vol. 5, doi: 10.1109/ISCAS.2005.1465666; posted in the Appendix. 
[5] L. R. Knudsen, M. J. B. Robshaw, The Block Cipher Companion, Springer, 2011.
[6] Muresan, R, ENGG4560 Laboratory Tutorial My Asynchronous AES Coprocessor Design.pdf

To understand the implementation review reference [6] found in this repository: ENGG4560 Laboratory Tutorial My Asynchronous AES Coprocessor Design.pdf
