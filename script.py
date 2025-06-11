import tkinter as tk
from tkinter import ttk, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
import socket
import threading
import queue

# ----------------------------
# VIGENÈRE CIPHER
# ----------------------------
def vigenere_encrypt(text, key):
    key = key.lower()
    result = []
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('a')
            encrypted = chr((ord(char) - offset + key_shift) % 26 + offset)
            result.append(encrypted)
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    result = []
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = ord('A') if char.isupper() else ord('a')
            key_char = key[key_index % len(key)]
            key_shift = ord(key_char) - ord('a')
            decrypted = chr((ord(char) - offset - key_shift + 26) % 26 + offset)
            result.append(decrypted)
            key_index += 1
        else:
            result.append(char)
    return ''.join(result)

# ----------------------------
# TEXT <-> BINARY
# ----------------------------
def text_to_binary(text):
    return ' '.join(f'{ord(c):08b}' for c in text)

def binary_to_text(bin_str):
    try:
        return ''.join(chr(int(b, 2)) for b in bin_str.strip().split())
    except ValueError:
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
    # Converte AMI de volta para um binário contínuo (o que já tava antes)
    continuous_binary = ''.join('0' if c == '0' else '1' for c in ami_str)
    # Divide o binário contínuo em pedaços de 8 bits
    chunks = [continuous_binary[i:i+8] for i in range(0, len(continuous_binary), 8)]  
    # Junta os pedaços com um espaço entre eles, recriando o formato original
    return ' '.join(chunks)

# ----------------------------
# MAIN APPLICATION CLASS
# ----------------------------
class NetworkCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Conversor AMI com Criptografia Vigenère - Network Edition")
        self.root.geometry("1200x900")

        self.data_queue = queue.Queue()
        self.stop_server_event = threading.Event()

        self.setup_gui()
        self.periodic_queue_check()

    def setup_gui(self):
        # --- Network Frame ---
        net_frame = ttk.LabelFrame(self.root, text="📡 Network Configuration", padding=(10, 5))
        net_frame.pack(padx=20, pady=10, fill="x")

        self.role_var = tk.StringVar(value="Client (Send)")
        tk.Label(net_frame, text="Role:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        role_menu = ttk.Combobox(net_frame, textvariable=self.role_var, values=["Client (Send)", "Server (Receive)"], state='readonly')
        role_menu.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        role_menu.bind("<<ComboboxSelected>>", self.toggle_role)

        tk.Label(net_frame, text="Server IP:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.ip_entry = tk.Entry(net_frame, width=20)
        self.ip_entry.grid(row=0, column=3, padx=5, pady=5, sticky='w')
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(net_frame, text="Port:").grid(row=0, column=4, padx=5, pady=5, sticky='w')
        self.port_entry = tk.Entry(net_frame, width=10)
        self.port_entry.grid(row=0, column=5, padx=5, pady=5, sticky='w')
        self.port_entry.insert(0, "9999")

        self.server_button = tk.Button(net_frame, text="Start Server", command=self.start_server, width=15)
        self.server_button.grid(row=0, column=6, padx=10, pady=5)
        self.server_status_label = tk.Label(net_frame, text="Server is offline.", fg="red", font=("Segoe UI", 9))
        self.server_status_label.grid(row=0, column=7, padx=5, pady=5, sticky="w")
        
        # --- Main Frame ---
        main_frame = ttk.LabelFrame(self.root, text="✉️ Message", padding=(10, 5))
        main_frame.pack(padx=20, pady=10, fill="both", expand=True)

        tk.Label(main_frame, text="Input Text:").pack(anchor='w')
        self.entrada_texto = tk.Text(main_frame, height=5, width=100)
        self.entrada_texto.pack(padx=5, pady=5, fill="x")

        tk.Label(main_frame, text="Vigenère Key:").pack(anchor='w', pady=(10,0))
        self.chave_entry = tk.Entry(main_frame, width=40)
        self.chave_entry.pack(padx=5, pady=5, anchor='w')

        self.process_button = tk.Button(main_frame, text="Encrypt and Send", command=self.process_and_send, width=30, height=2)
        self.process_button.pack(pady=15)

        tk.Label(main_frame, text="Output:").pack(anchor='w')
        self.saida_texto = tk.Text(main_frame, height=12, width=120)
        self.saida_texto.pack(padx=5, pady=10, fill="both", expand=True)

        # --- Matplotlib Plot ---
        plot_frame = ttk.LabelFrame(self.root, text="📊 AMI Waveform", padding=(10, 5))
        plot_frame.pack(padx=20, pady=10, fill="x")
        self.fig, self.ax = plt.subplots(figsize=(12, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=plot_frame)
        self.canvas.get_tk_widget().pack()
        
        self.toggle_role() # Set initial GUI state

    def toggle_role(self, event=None):
        """Enable/disable GUI elements based on the selected role."""
        if self.role_var.get() == "Server (Receive)":
            self.entrada_texto.config(state=tk.DISABLED)
            self.process_button.config(state=tk.DISABLED)
            self.ip_entry.config(state=tk.DISABLED)
            self.server_button.config(state=tk.NORMAL)
        else: # Client
            self.entrada_texto.config(state=tk.NORMAL)
            self.process_button.config(state=tk.NORMAL)
            self.ip_entry.config(state=tk.NORMAL)
            self.server_button.config(state=tk.DISABLED)

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

    def process_and_send(self):
        """Client-side logic: Encrypts, displays locally, and sends data."""
        text = self.entrada_texto.get("1.0", tk.END).strip()
        key = self.chave_entry.get().strip()
        if not text or not key:
            messagebox.showerror("Error", "Please enter a message and a key.")
            return

        try:
            encrypted = vigenere_encrypt(text, key)
            binary = text_to_binary(encrypted)
            ami = binary_to_ami(binary)

            self.saida_texto.delete("1.0", tk.END)
            self.saida_texto.insert(tk.END, f"--- SENDER'S LOG ---\n")
            self.saida_texto.insert(tk.END, f"📨 Original Message:\n{text}\n\n")
            self.saida_texto.insert(tk.END, f"🔐 Encrypted Message (Vigenère):\n{encrypted}\n\n")
            self.saida_texto.insert(tk.END, f"💾 Binary:\n{binary}\n\n")
            self.saida_texto.insert(tk.END, f"⚡ AMI to be Sent:\n{ami}")
            self.plot_wave(ami)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.ip_entry.get(), int(self.port_entry.get())))
                s.sendall(ami.encode('utf-8'))
            messagebox.showinfo("Success", "Message sent successfully!")

        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "Connection refused. Is the server running and the IP/Port correct?")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            
    def server_thread_function(self, host, port):
        """Thread function to listen for incoming connections."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                s.listen()
                
                while not self.stop_server_event.is_set():
                    s.settimeout(1) 
                    try:
                        conn, addr = s.accept()
                        with conn:
                            self.root.after(0, self.server_status_label.config, {'text': f"Receiving from {addr[0]}...", 'fg': "blue"})
                            data = conn.recv(4096).decode('utf-8')
                            if data:
                                self.data_queue.put(data)
                            self.root.after(2000, lambda: self.server_status_label.config(text=self.listening_message, fg="green"))
                    except socket.timeout:
                        continue
            except Exception as e:
                 if not self.stop_server_event.is_set():
                    self.server_status_label.config(text=f"Server Error: {e}", fg="red")
            finally:
                self.server_status_label.config(text="Server is offline.", fg="red")

    def start_server(self):
        """Starts the server and displays the local IP."""
        host_ip_to_bind = '0.0.0.0'  # Bind to all network interfaces
        port = int(self.port_entry.get())
        
        try:
            # This is a reliable way to get the primary local IP address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80)) # Connect to an external address
                local_ip = s.getsockname()[0]
        except Exception:
            # Fallback if the above method fails
            local_ip = "127.0.0.1"
            messagebox.showwarning("Network Warning", "Could not determine local IP automatically. Displaying 127.0.0.1. Please check your network connection.")

        self.listening_message = f"Listening on IP {local_ip} / Port {port}"
        self.server_status_label.config(text=self.listening_message, fg="green")
        
        self.stop_server_event.clear()
        
        server_thread = threading.Thread(target=self.server_thread_function, args=(host_ip_to_bind, port), daemon=True)
        server_thread.start()
        self.server_button.config(text="Stop Server", command=self.stop_server)

    def stop_server(self):
        """Stops the server thread."""
        self.stop_server_event.set()
        self.server_status_label.config(text="Server is offline.", fg="red")
        self.server_button.config(text="Start Server", command=self.start_server)

    def periodic_queue_check(self):
        """Periodically check the queue for new data from the network thread."""
        while not self.data_queue.empty():
            ami_data = self.data_queue.get()
            self.process_received_data(ami_data)
        self.root.after(100, self.periodic_queue_check)

    def process_received_data(self, ami):
        """Server-side logic: Processes received AMI data and updates the GUI."""
        key = self.chave_entry.get().strip()
        if not key:
            messagebox.showwarning("Warning", "No key provided for decryption. The result may be incorrect.")
        
        binary = ami_to_binary(ami)
        encrypted_text = binary_to_text(binary)
        decrypted_text = vigenere_decrypt(encrypted_text, key)

        self.saida_texto.delete("1.0", tk.END)
        self.saida_texto.insert(tk.END, f"--- RECEIVER'S LOG ---\n")
        self.saida_texto.insert(tk.END, f"⚡ Received AMI:\n{ami}\n\n")
        self.saida_texto.insert(tk.END, f"💾 Converted to Binary:\n{binary}\n\n")
        self.saida_texto.insert(tk.END, f"🔐 Converted to Encrypted Text:\n{encrypted_text}\n\n")
        self.saida_texto.insert(tk.END, f"📨 Decrypted Original Message:\n{decrypted_text}")
        
        self.plot_wave(ami)
        
    def on_closing(self):
        """Handle window closing."""
        self.stop_server_event.set() 
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkCipherApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()