import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import socket
import threading
import queue
import base64 # Importado para transportar dados binários de forma segura

# ----------------------------
# CRIPTOGRAFIA ASSIMÉTRICA RSA (com a biblioteca cryptography)
# ----------------------------
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# --- Funções para gerenciar chaves RSA ---
def generate_keys():
    """Gera um par de chaves RSA (privada e pública)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()  # <-- ADICIONE ESTE PARÂMETRO
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    """Converte um objeto de chave privada para o formato PEM (texto)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def serialize_public_key(public_key):
    """Converte um objeto de chave pública para o formato PEM (texto)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def deserialize_public_key(pem_data):
    """Converte um texto PEM de volta para um objeto de chave pública."""
    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=default_backend()  # <-- ADICIONE ESTE PARÂMETRO
    )

# --- Funções para criptografar e descriptografar com RSA ---
def rsa_encrypt(public_key, message):
    """Criptografa a mensagem (bytes) usando uma chave pública."""
    message_bytes = message.encode('utf-8')
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    """Descriptografa o texto cifrado (bytes) usando uma chave privada."""
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        return f"ERRO DE DESCRIPTOGRAFIA: {e}. A chave privada está correta?"

# ----------------------------
# TEXT <-> BINARY
# ----------------------------
def text_to_binary(text):
    return ' '.join(f'{ord(c):08b}' for c in text)

def binary_to_text(bin_str):
    try:
        return ''.join(chr(int(b, 2)) for b in bin_str.strip().split())
    except (ValueError, TypeError):
        return "Erro: Binário malformado."

# ----------------------------
# BINARY <-> AMI
# ----------------------------
def binary_to_ami(bin_str):
    ami = []
    level = 1
    for b in bin_str.replace(" ", ""):
        if b == '0':
            ami.append('0')
        else:
            ami.append('+' if level == 1 else '-')
            level *= -1
    return ''.join(ami)

def ami_to_binary(ami_str):
    continuous_binary = ''.join('0' if c == '0' else '1' for c in ami_str)
    chunks = [continuous_binary[i:i+8] for i in range(0, len(continuous_binary), 8)]
    return ' '.join(chunks)

# ----------------------------
# MAIN APPLICATION CLASS
# ----------------------------
# (O código anterior a esta classe permanece o mesmo)

# ----------------------------
# MAIN APPLICATION CLASS
# ----------------------------
class NetworkCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("BROADCAST com Criptografia Assimétrica RSA") # Título atualizado
        self.root.geometry("1200x950")

        self.data_queue = queue.Queue()
        self.stop_server_event = threading.Event()

        self.private_key = None
        self.public_key = None

        self.FIXED_PORT = 9999

        self.setup_gui()
        self.periodic_queue_check()

    def setup_gui(self):
        # --- Network Frame Modificado para Broadcast ---
        net_frame = ttk.LabelFrame(self.root, text="📡 Network Configuration (UDP Broadcast)", padding=(10, 5))
        net_frame.pack(padx=20, pady=10, fill="x")
        self.role_var = tk.StringVar(value="Client (Send)")
        tk.Label(net_frame, text="Role:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        role_menu = ttk.Combobox(net_frame, textvariable=self.role_var, values=["Client (Send)", "Server (Receive)"], state='readonly')
        role_menu.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        role_menu.bind("<<ComboboxSelected>>", self.toggle_role)
        
        # O campo de IP agora é para o endereço de Broadcast
        tk.Label(net_frame, text="Broadcast IP:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.ip_entry = tk.Entry(net_frame, width=20)
        self.ip_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')
        # Preenche com o endereço de broadcast mais comum
        self.ip_entry.insert(0, "255.255.255.255") 

        # tk.Label(net_frame, text="Port:").grid(row=0, column=4, padx=5, pady=5, sticky='w')
        # self.port_entry = tk.Entry(net_frame, width=10)
        # self.port_entry.grid(row=0, column=5, padx=5, pady=5, sticky='w')
        # self.port_entry.insert(0, "9999")
        
        self.server_button = tk.Button(net_frame, text="Start Listening", command=self.start_server, width=15) # Texto do botão atualizado
        self.server_button.grid(row=0, column=6, padx=10, pady=5)
        self.server_status_label = tk.Label(net_frame, text="Listener is offline.", fg="red", font=("Segoe UI", 9))
        self.server_status_label.grid(row=0, column=7, padx=5, pady=5, sticky="w")

        # --- O resto da GUI (Key Management, Main Frame, Plot) permanece o mesmo ---
        # ... (código da GUI omitido por brevidade, é o mesmo da versão anterior) ...
        keys_frame = ttk.LabelFrame(self.root, text="🔑 Asymmetric Key Management (RSA)", padding=(10, 5))
        keys_frame.pack(padx=20, pady=5, fill="x")
        tk.Button(keys_frame, text="Gerar Meu Par de Chaves", command=self.generate_key_pair_gui).grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky='w')
        pub_key_header_frame = tk.Frame(keys_frame)
        pub_key_header_frame.grid(row=1, column=0, sticky='ew')
        tk.Label(pub_key_header_frame, text="Minha Chave Pública (Compartilhe esta):").pack(side=tk.LEFT, padx=5)
        tk.Button(pub_key_header_frame, text="📋 Copiar", command=self.copy_public_key_to_clipboard).pack(side=tk.RIGHT, padx=5)
        self.my_public_key_text = scrolledtext.ScrolledText(keys_frame, height=4, width=60, wrap=tk.WORD, state=tk.DISABLED)
        self.my_public_key_text.grid(row=2, column=0, padx=5, pady=2, sticky='w')
        tk.Label(keys_frame, text="Minha Chave Privada (NÃO COMPARTILHE!):").grid(row=1, column=1, padx=5, sticky='w')
        self.my_private_key_text = scrolledtext.ScrolledText(keys_frame, height=4, width=60, wrap=tk.WORD, state=tk.DISABLED)
        self.my_private_key_text.grid(row=2, column=1, padx=5, pady=2, sticky='w')
        main_frame = ttk.LabelFrame(self.root, text="✉️ Message", padding=(10, 5))
        main_frame.pack(padx=20, pady=10, fill="both", expand=True)
        tk.Label(main_frame, text="Chave Pública do Destinatário:").pack(anchor='w')
        self.recipient_public_key_text = scrolledtext.ScrolledText(main_frame, height=4, width=120)
        self.recipient_public_key_text.pack(padx=5, pady=5, fill="x")
        tk.Label(main_frame, text="Texto para Enviar:").pack(anchor='w')
        self.entrada_texto = tk.Text(main_frame, height=3, width=100)
        self.entrada_texto.pack(padx=5, pady=5, fill="x")
        self.process_button = tk.Button(main_frame, text="Encrypt and Broadcast", command=self.process_and_send, width=30, height=2)
        self.process_button.pack(pady=10)
        tk.Label(main_frame, text="Output Log:").pack(anchor='w')
        self.saida_texto = scrolledtext.ScrolledText(main_frame, height=10, width=120)
        self.saida_texto.pack(padx=5, pady=5, fill="both", expand=True)
        plot_frame = ttk.LabelFrame(self.root, text="📊 AMI Waveform", padding=(10, 5))
        plot_frame.pack(padx=20, pady=10, fill="x")
        self.fig, self.ax = plt.subplots(figsize=(12, 2.5))
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.get_tk_widget().pack()
        self.toggle_role()

    # NOVA FUNÇÃO para copiar a chave para a área de transferência
    def copy_public_key_to_clipboard(self):
        if not self.public_key:
            messagebox.showwarning("Aviso", "Gere um par de chaves primeiro antes de copiar.")
            return
        public_key_pem = self.my_public_key_text.get("1.0", tk.END).strip()
        if public_key_pem:
            self.root.clipboard_clear()
            self.root.clipboard_append(public_key_pem)
            messagebox.showinfo("Copiado!", "A chave pública foi copiada para a área de transferência.")
        else:
            messagebox.showerror("Erro", "Não há chave pública para copiar.")

    def generate_key_pair_gui(self):
        """Função chamada pelo botão para gerar e exibir as chaves."""
        self.private_key, self.public_key = generate_keys()

        pub_pem = serialize_public_key(self.public_key)
        priv_pem = serialize_private_key(self.private_key)

        self.my_public_key_text.config(state=tk.NORMAL)
        self.my_public_key_text.delete("1.0", tk.END)
        self.my_public_key_text.insert(tk.END, pub_pem)
        self.my_public_key_text.config(state=tk.DISABLED)

        self.my_private_key_text.config(state=tk.NORMAL)
        self.my_private_key_text.delete("1.0", tk.END)
        self.my_private_key_text.insert(tk.END, priv_pem)
        self.my_private_key_text.config(state=tk.DISABLED)

        messagebox.showinfo("Sucesso", "Par de chaves RSA gerado com sucesso!")
        
    # Restante das funções (process_and_send, process_received_data, etc.)
    # permanecem as mesmas da versão anterior.
    # ... cole o restante do seu código aqui ...
    def process_and_send(self):
        """Lógica do Cliente: Criptografa e envia a mensagem em BROADCAST via UDP."""
        text = self.entrada_texto.get("1.0", tk.END).strip()
        recipient_pem = self.recipient_public_key_text.get("1.0", tk.END).strip()

        if not text or not recipient_pem:
            messagebox.showerror("Erro", "Insira a mensagem e a chave pública do destinatário.")
            return

        try:
            # Lógica de criptografia e codificação (já estava correta)
            recipient_public_key = deserialize_public_key(recipient_pem)
            encrypted_bytes = rsa_encrypt(recipient_public_key, text)
            encrypted_b64_str = base64.b64encode(encrypted_bytes).decode('utf-8')
            binary = text_to_binary(encrypted_b64_str)
            ami = binary_to_ami(binary)

            # Lógica de Rede UDP (já estava correta)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            broadcast_address = (self.ip_entry.get(), self.FIXED_PORT)
            s.sendto(ami.encode('utf-8'), broadcast_address)
            s.close()
            
            # --- ATUALIZAÇÃO DO LOG DA GUI ---
            self.saida_texto.delete("1.0", tk.END)
            self.saida_texto.insert(tk.END, f"--- SENDER'S LOG ---\n")
            self.saida_texto.insert(tk.END, f"📨 Original Message:\n{text}\n\n")
            self.saida_texto.insert(tk.END, f"🔐 Encrypted Message (RSA, as bytes):\n{encrypted_bytes}\n\n")
            self.saida_texto.insert(tk.END, f"📦 Base64 Encoded (for transport):\n{encrypted_b64_str}\n\n")
            
            # --- LINHA ADICIONADA AQUI ---
            self.saida_texto.insert(tk.END, f"💾 Binary of Base64:\n{binary}\n\n")
            
            self.saida_texto.insert(tk.END, f"⚡ AMI to be Sent:\n{ami}")
            self.plot_wave(ami)
            
            messagebox.showinfo("Success", f"Message broadcasted to {broadcast_address[0]}!")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}\n\nVerifique se a chave pública do destinatário é válida.")

    def process_received_data(self, ami, sender_addr):
        """Processa os dados recebidos via broadcast."""
        if not self.private_key:
            # Apenas mostra no log, sem pop-up para não atrapalhar múltiplos recebimentos
            self.saida_texto.insert("1.0", f"--- IGNORING BROADCAST from {sender_addr[0]} (No private key loaded) ---\n\n")
            return

        # Atualiza o status para mostrar de quem recebeu
        self.server_status_label.config(text=f"Received broadcast from {sender_addr[0]}", fg="blue")
        self.root.after(3000, lambda: self.server_status_label.config(text=self.listening_message, fg="green"))

        # ... (lógica de decodificação e descriptografia permanece a mesma) ...
        binary = ami_to_binary(ami)
        received_b64_str = binary_to_text(binary)
        
        try:
            encrypted_bytes = base64.b64decode(received_b64_str)
            decrypted_text = rsa_decrypt(self.private_key, encrypted_bytes)

            self.saida_texto.delete("1.0", tk.END)
            self.saida_texto.insert(tk.END, f"--- RECEIVER'S LOG (from {sender_addr[0]}) ---\n")
            self.saida_texto.insert(tk.END, f"⚡ Received AMI:\n{ami}\n\n")
            self.saida_texto.insert(tk.END, f"📦 Received Base64 Text:\n{received_b64_str}\n\n")
            self.saida_texto.insert(tk.END, f"📨 Decrypted Original Message:\n{decrypted_text}")
        except Exception:
            # Se a descriptografia falhar (porque a mensagem não era para esta chave privada),
            # apenas registramos isso discretamente.
            self.saida_texto.delete("1.0", tk.END)
            self.saida_texto.insert(tk.END, f"--- RECEIVER'S LOG (from {sender_addr[0]}) ---\n")
            self.saida_texto.insert(tk.END, "Intercepted a message, but it was not for me (decryption failed).\n")

        self.plot_wave(ami)
        
    def toggle_role(self, event=None):
        is_server = self.role_var.get() == "Server (Receive)"
        client_state = tk.NORMAL if not is_server else tk.DISABLED
        server_state = tk.NORMAL if is_server else tk.DISABLED
        self.entrada_texto.config(state=client_state)
        self.process_button.config(state=client_state)
        self.ip_entry.config(state=client_state)
        self.recipient_public_key_text.config(state=client_state)
        self.server_button.config(state=server_state)

    def plot_wave(self, ami):
        x, y, tempo = [], [], 0
        for simbolo in ami:
            nivel = 0
            if simbolo == '+': nivel = 1
            elif simbolo == '-': nivel = -1
            x.extend([tempo, tempo + 1])
            y.extend([nivel, nivel])
            tempo += 1
        
        self.ax.clear()
        self.ax.set_title("AMI Waveform")
        self.ax.set_xlabel("Time"); self.ax.set_ylabel("Level")
        self.ax.set_ylim(-1.5, 1.5); self.ax.set_xlim(0, max(1, tempo))
        self.ax.grid(True)
        self.ax.plot(x, y, drawstyle='steps-post', linewidth=2, color='blue')
        self.fig.tight_layout()
        self.canvas.draw()
            
    def server_thread_function(self, host, port):
        """Thread do Servidor: Escuta por pacotes UDP em uma porta."""
        # Cria o socket UDP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                # Binda o socket para escutar em todas as interfaces de rede
                s.bind((host, port))
                
                while not self.stop_server_event.is_set():
                    s.settimeout(1.0)
                    try:
                        # Espera por dados. recvfrom retorna os dados e o endereço de quem enviou
                        data_bytes, addr = s.recvfrom(8192) 
                        data = data_bytes.decode('utf-8')
                        
                        # Coloca os dados e o endereço do remetente na fila
                        if data:
                            self.data_queue.put({'data': data, 'sender': addr})
                            
                    except socket.timeout:
                        continue # Volta para o início do loop para checar self.stop_server_event
            
            except Exception as e:
                if not self.stop_server_event.is_set():
                    # Usamos after para garantir que a atualização da GUI seja feita na thread principal
                    self.root.after(0, self.server_status_label.config, {'text': f"Server Error: {e}", 'fg': "red"})
            finally:
                self.root.after(0, self.server_status_label.config, {'text': "Listener is offline.", 'fg': "red"})

    def start_server(self):
        """Inicia a thread que escuta por pacotes UDP."""
        # '0.0.0.0' significa escutar em todas as interfaces de rede disponíveis
        host_ip_to_bind = '0.0.0.0'
        port = int(self.port_entry.get())
        
        self.listening_message = f"Listening for broadcasts on port {port}"
        self.server_status_label.config(text=self.listening_message, fg="green")
        
        self.stop_server_event.clear()
        
        server_thread = threading.Thread(target=self.server_thread_function, args=(host_ip_to_bind, port), daemon=True)
        server_thread.start()
        
        self.server_button.config(text="Stop Listening", command=self.stop_server)

    def stop_server(self):
        """Para a thread de escuta."""
        self.stop_server_event.set()
        self.server_status_label.config(text="Listener is offline.", fg="red")
        self.server_button.config(text="Start Listening", command=self.start_server)
       
    def periodic_queue_check(self):
        """Verifica a fila por novos dados recebidos."""
        while not self.data_queue.empty():
            # Pega o dicionário completo da fila
            received_info = self.data_queue.get()
            ami_data = received_info['data']
            sender_addr = received_info['sender']
            
            # Passa os dados e o endereço do remetente para a função de processamento
            self.process_received_data(ami_data, sender_addr)
            
        self.root.after(100, self.periodic_queue_check)

    def on_closing(self):
        self.stop_server_event.set()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkCipherApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()