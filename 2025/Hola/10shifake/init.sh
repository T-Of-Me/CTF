echo "${GZCTF_FLAG:-HOLACTF{default_fake_flag}}" > /app/flag.txt
chmod 444 /app/flag.txt
unset GZCTF_FLAG
export SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
echo "[+] SECRET_KEY generated: $SECRET_KEY" >&2
python3 /app/app.py
