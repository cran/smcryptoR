% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/sm2.R
\name{sm2_gen_keypair}
\alias{sm2_gen_keypair}
\alias{sm2_pk_from_sk}
\alias{sm2_privkey_valid}
\alias{sm2_pubkey_valid}
\alias{sm2_keypair_from_pem_file}
\alias{sm2_keypair_to_pem_file}
\alias{sm2_pubkey_from_pem_file}
\alias{sm2_pubkey_to_pem_file}
\title{SM2 Key Pair}
\usage{
sm2_gen_keypair()

sm2_pk_from_sk(private_key)

sm2_privkey_valid(private_key)

sm2_pubkey_valid(public_key)

sm2_keypair_from_pem_file(pem_file)

sm2_keypair_to_pem_file(private_key, pem_file)

sm2_pubkey_from_pem_file(pem_file)

sm2_pubkey_to_pem_file(public_key, pem_file)
}
\arguments{
\item{private_key}{a private key represented as a hexadecimal string}

\item{public_key}{a public key represented as a hexadecimal string}

\item{pem_file}{local pem file path}
}
\value{
\describe{
  \item{\link{sm2_gen_keypair}}{returns a list contains a random private key and the corresponding public key}
  \item{\link{sm2_pk_from_sk}}{returns a character string, the public key exported from a private key}
  \item{\link{sm2_privkey_valid}}{returns 1 if valid, 0 if invalid}
  \item{\link{sm2_pubkey_valid}}{returns 1 if valid, 0 if invalid}
  \item{\link{sm2_keypair_from_pem_file}}{returns a list contains a random private key and the corresponding public key}
  \item{\link{sm2_keypair_to_pem_file}}{returns nothing, and a local file contains the keypair will be saved in the specified path}
  \item{\link{sm2_pubkey_from_pem_file}}{returns a character string, the public key saved in the local file}
  \item{\link{sm2_pubkey_to_pem_file}}{returns nothing, and a local file contains the public key will be saved in the specified path}
}
}
\description{
In the SM2 encryption algorithm, the private key and public key appear in pairs.
The private key is a 64-bit hexadecimal string, and the public key is a
128-bit hexadecimal string, excluding the "04" prefix at the beginning.
The public key is included in the private key and can be derived from the
private key. We use the public key for encryption, the private key for decryption,
the private key for signing, and the public key for verification.
}
\details{
\describe{
  \item{\link{sm2_gen_keypair}}{generate a ramdom key pair}
  \item{\link{sm2_pk_from_sk}}{export public key from a private key}
  \item{\link{sm2_privkey_valid}}{check whether a private key is legal}
  \item{\link{sm2_pubkey_valid}}{check whether a public key is legal}
  \item{\link{sm2_keypair_from_pem_file}}{import private key from a local pem file}
  \item{\link{sm2_keypair_to_pem_file}}{save a private key to a local pem file}
  \item{\link{sm2_pubkey_from_pem_file}}{import public key from a local pem file}
  \item{\link{sm2_pubkey_to_pem_file}}{save a public key to a local pem file}
}
}
\examples{
## generate a ramdom keypair
keypair <- sm2_gen_keypair()
keypair$private_key
keypair$public_key
## export public key from private key
sm2_pk_from_sk(keypair$private_key)
## check whether the private key is legal
sm2_privkey_valid(keypair$private_key)
## check whether the public key is legal
sm2_pubkey_valid(keypair$public_key)
\dontrun{
  sm2_keypair_to_pem_file(keypair, 'keypair.pem')
  sm2_keypair_from_pem_file('keypair.pem')
  sm2_pubkey_to_pem_file(keypair$public_key, 'pubkey.pem')
  sm2_pubkey_from_pem_file('pubkey.pem')
}
}
