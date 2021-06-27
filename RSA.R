# ==============================================================================================
#Language: R
#Library: OpenSSL
# ==============================================================================================

# Tipos primitivos de dados int ou double registram números em 4 ou 8 bytes (com precisão finita)
# tipos acima são suficientes para muitas aplicações, mas para realizar criptografia
# são necessários cálcula aritiméticos com números muito maiores (bigint) e sem perder precisão

# OpenSSL usa o tipo bignum para as operações aritiméticas utilizando operadores como os abaixo citados:
# +, -, *, ^, %%, %/%, ==, !=, <, <=, > and >=.


library(openssl)


# =================================================================================================
#Implementação direta 

rm(list = ls())
key <- rsa_keygen(512)
pubkey <- key$pubkey
text <- charToRaw("Habib, arruma minhas notas no Teams")
class (text)
ciphertext <- rsa_encrypt(text, pubkey)
rawToChar(rsa_decrypt(ciphertext, key))

# =================================================================================================
#Implementação manual (BIGINT)

rm(list = ls())
Privatekey <- rsa_keygen(512)
PublicKey <- Privatekey$pubkey
Msg <- bignum(charToRaw("Habib, arruma minhas notas no Teams"))
class (Msg)
print(Msg)

# A chave pública: o par (n,e)
e <- PublicKey$data$e
n <- PublicKey$data$n

# Mensagem original em formato bigint ainda não criptografada
Msg

MsgCripto <- (Msg ^ e) %% n # https://pt.wikipedia.org/wiki/RSA_(sistema_criptogr%C3%A1fico)

# Mensagem original em formato bigint ja criptografada
MsgCripto

base64_encode(MsgCripto)
d <- Privatekey$data$d

out <- bignum_mod_exp(MsgCripto, d, n)
out
class(out)
rawToChar(out)

# =================================================================================================
#Implementação manual (RAW)


rm(list = ls())

#	Cria chave privada
privateKey <- rsa_keygen(512)
class (privateKey)

#	Cria Chave públic
publicKey <- privateKey$pubkey
class (publicKey)

text <-("Habib, arruma minhas notas no Teams")
class (text)

# charToRaw 
# converte para um vetor onde cada byte e representado separadamente como um par de dígitos hexadecimais
text <- charToRaw(text)
class (text)
text

# Criptografa a chave temporária usando a chave RSA pública
ciphertext <- rsa_encrypt(text, publicKey)
class (ciphertext)
ciphertext

# Descriptografa o objeto anterior
x <- rsa_decrypt(ciphertext, privateKey)

# converte objeto ja descriptografado de Raw para Character
rawToChar(x)
