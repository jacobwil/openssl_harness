#!/usr/bin/env bash

# Run this script with an argument of the path of your openssl binary to fill the certs folder with a big pile of
# stacked pem certificates
#set -x
set -euo pipefail
if [[ -z "$1" ]];
  then
  echo "You need to provide the path to your openssl binary as an argument to this script"
  exit 1
fi

if [[ ! -f "$1" ]];
  then
  echo "${1} isn't a valid path to a file"
  exit 1
fi

CERT_OUTPUT_DIR="${CERT_OUTPUT_DIR:-./certs}"
mkdir -p ${CERT_OUTPUT_DIR}
cp openssl_req_conf.conf ${CERT_OUTPUT_DIR}

DHPARAM_OUTPUT_DIR="${DHPARAM_OUTPUT_DIR:-./dhparam}"
mkdir -p ${DHPARAM_OUTPUT_DIR}

# Generate keys and certificates

OPENSSL_BIN="$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"

# Print out the openssl version
${OPENSSL_BIN} version

# Oakley curves cause issues. `${OPENSSL_BIN} ecparam -list_curves` prints warnings too.
${OPENSSL_BIN} ecparam -list_curves | grep -oE '[^:]+ *:' | grep -oE '[^ :]+'
curves_list_raw=$(${OPENSSL_BIN} ecparam -list_curves | grep -oE '[^:]+ *:' | grep -oE '[^ :]+')

# Gotta be honest, bash arrays are ridiculous
curves_list=($(echo ${curves_list_raw}))


pushd "${CERT_OUTPUT_DIR}"

echo "Generating elliptic curve certificates"
for curve_name in "${curves_list[@]}"
  do
  echo "Creating an EC cert for ${curve_name} -> ec_${curve_name}_server.pem"
  ${OPENSSL_BIN} req -x509 -sha256 -config openssl_req_conf.conf -extensions 'server' \
              -nodes -days 3653 -newkey ec:<(${OPENSSL_BIN} ecparam -name "${curve_name}") \
              -keyout "ec_${curve_name}_server.key.pem" -out "ec_${curve_name}_server.cert.pem" \
              ||  { echo -e "\n\n!!!!! Failed to make ec_${curve_name}_server.pem\n\n"; continue; }
  # Consolidate into a stacked pem
  cat "ec_${curve_name}_server.key.pem" "ec_${curve_name}_server.cert.pem" > "ec_${curve_name}_server.pem"
  rm "ec_${curve_name}_server.key.pem" "ec_${curve_name}_server.cert.pem"
done
echo ${curves_list_raw}
echo ${curves_list[@]}

echo "Generating RSA certificates"
rsa_size_list=( 1024 1280 1536 2048 3072 4096 )

for size in "${rsa_size_list[@]}";
  do
  echo "Creating an RSA cert for size ${size} -> rsa_${size}_server.cert.pem"
  ${OPENSSL_BIN} req -x509 -sha256 -config openssl_req_conf.conf -extensions 'server' \
              -nodes -days 3653 -newkey "rsa:${size}" \
              -keyout "rsa_${size}_server.key.pem" -out "rsa_${size}_server.cert.pem" \
              ||  { echo -e "\n\n!!!!! Failed to make rsa_${size}_server.pem\n\n"; continue; }
  # Consolidate into a stacked pem
  cat "rsa_${size}_server.key.pem" "rsa_${size}_server.cert.pem" > "rsa_${size}_server.pem"
  rm "rsa_${size}_server.key.pem" "rsa_${size}_server.cert.pem"
done

echo "Generating DSA certificates"
dsa_size_list=( 1024 1280 1536 2048 3072 4096 )
for size in "${dsa_size_list[@]}";
  do
  echo "Creating a DSA cert for size ${size} -> dsa_${size}_server.cert.pem"
  ${OPENSSL_BIN} req -x509 -sha256 -config openssl_req_conf.conf -extensions 'server' \
              -nodes -days 3653 -newkey dsa:<(${OPENSSL_BIN} dsaparam "${size}") \
              -keyout "dsa_${size}_server.key.pem" -out "dsa_${size}_server.cert.pem" \
              ||  { echo -e "\n\n!!!!! Failed to make dsa_${size}_server.pem\n\n"; continue; }
  # Consolidate into a stacked pem
  cat "dsa_${size}_server.key.pem" "dsa_${size}_server.cert.pem" > "dsa_${size}_server.pem"
  rm "dsa_${size}_server.key.pem" "dsa_${size}_server.cert.pem"
done

popd

pushd "${DHPARAM_OUTPUT_DIR}"
echo "Generating Diffie-Hellman parameters"
dh_size_list=( 1024 1280 1536 2048 3072 4096 )
for size in "${dh_size_list[@]}";
  do
  echo "Creating a DH paramater file for size ${size} -> dh_${size}.pem"
  ${OPENSSL_BIN} dhparam ${size} -out "dh_${size}.pem" \
              ||  { echo -e "\n\n!!!!! Failed to make dh_${size}.pem\n\n"; continue; }
done

exit
