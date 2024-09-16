import tkinter as tk
from tkinter import simpledialog, Text, Entry, Button, filedialog, ttk
import threading
import socket
import pickle
import sys
import time

class Message: #The message, ack, and check in class. This will be used to differentiate between a message received and an ack.
    def __init__(self, message, seq_num):
        self.message = message
        self.seq_num = seq_num

    def get_message(self):
        return self.message

    def get_seq_num(self):
        return self.seq_num

class ACK:
    def __init__(self, ack_num, ack_type='message'):
        self.ack_num = ack_num
        self.ack_type = ack_type

    def get_ack_num(self):
        return self.ack_num

    def get_ack_type(self):
        return self.ack_type


class checkIn:
    def __init__(self):
        self.message = "checking in..."

class ChatApp: #Setting up the GUI and the global variables to be used
    def __init__(self, master):
        master.title(f"Chat With {sys.argv[2]}")
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', background='#333', foreground='white', font=('Helvetica', 10))
        style.map('TButton', background=[('active', '#555')])

        self.setup_widgets(master)
        self.host = '0.0.0.0'
        self.port = int(sys.argv[1])
        self.target_host = sys.argv[2]
        self.target_port = int(sys.argv[3])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        self.messages_sent = [] #This is the array to keep track of the sent messages in case the app needs to retransmit unACKed messages
        self.correct_messages = [] #This is the array that gets updated by the receiver whenever it ACKs a message for the first time, signaling it should be part of the messages in the app. This was mainly for testing purposes early on.
        self.acks_received = {} #This is to keep track of the received ACKs + the number of times that seq num has been ACKed
        self.correct_sent = [] #similar to correct_messages, mainly for testing purposes, to compare with it.
        self.message_timers = {} #Each message sent would have a timer and be canceled when received the ACK back. If not canceled, timeout and retransmit
        self.expected_seq_num = 0 #Used by the receiver to know what to ACK and what not to ACK (Ack only the successor to the previously ACKed)
        self.seq_num = 1 #Starting sequence number at the beginning of the app
        self.file_selected = '' #GUI feature to show what file is selected to send
        self.file_sock = None
        self.last_check_in_ack_sent = None #Used for check in in case of timeout and retransmitting the check in
        threading.Thread(target=self.checkInWithPeer, daemon=True).start() #check in
        threading.Thread(target=self.tcp_server, daemon=True).start() #TCP Server for File Transfer
        threading.Thread(target=self.receive, daemon=True).start() #Receive thread in order for the socket to act both as server and client

    def setup_widgets(self, master):
        master.configure(bg='#f0f0f0') #More GUI Setup

        self.message_frame = ttk.Frame(master, padding="10")
        self.message_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.text_area = Text(self.message_frame, height=15, width=50, state='disabled', wrap='word', font=('Helvetica', 11))
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(self.message_frame, command=self.text_area.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area['yscrollcommand'] = scrollbar.set

        self.message_entry = ttk.Entry(master, font=('Helvetica', 11))
        self.message_entry.pack(fill=tk.X, padx=10, pady=5)
        self.message_entry.bind("<Return>", lambda event: self.send_contents())

        self.send_button = ttk.Button(master, text="Send", command=self.send_contents)
        self.send_button.pack(side=tk.RIGHT, padx=10, pady=5)

        self.file_frame = ttk.Frame(master, padding="3 3 12 12")
        self.file_frame.pack(fill=tk.X, padx=10, pady=5)
        self.file_select_button = ttk.Button(self.file_frame, text="Select File", command=self.select_file)
        self.file_select_button.pack(side=tk.LEFT)
        self.file_label = ttk.Label(self.file_frame, text="No file selected", font=('Helvetica', 10))
        self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.text_area.tag_configure('right', justify=tk.RIGHT, background='lightblue', foreground='black', font=('Arial', 12, 'bold'), lmargin1=10, lmargin2=10, rmargin=10, spacing3=4)

        self.text_area.tag_configure('left', justify=tk.LEFT, background='lightgreen', foreground='black', font=('Arial', 12), lmargin1=10, lmargin2=10, rmargin=10, spacing3=4)

        self.text_area.config(state='disabled')

    def checkInWithPeer(self):
        check_in_msg = checkIn()
        data = pickle.dumps(check_in_msg)
        self.sock.sendto(data, (self.target_host, self.target_port))
        print("Check-in message sent to peer.")
        self.check_in_timer = threading.Timer(3.0, self.checkInWithPeer)  # Retry every 3 seconds until ACK for checkin is received
        self.check_in_timer.start()

    def stopCheckInTimer(self):
        if self.check_in_timer is not None: #Stop timer once received ack
            self.check_in_timer.cancel()
            self.check_in_timer = None


    def select_file(self): #Select file before sending
        self.file_selected = filedialog.askopenfilename()
        if self.file_selected:
            name = self.file_selected.split("/")[-1]
            self.file_label.configure(text=f"Selected: {name}")

    def send_contents(self): #Send both message and file in case user has both ready to send
        if (self.file_selected != ''):
            self.tcp_client()
        self.send_message()


    def tcp_server(self):
        buffer_size = 65536 #Allow up to 64kB to transfer
        host, port = self.host, 50001

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((host, port))
            server_socket.listen()
            print(f"Listening for connections on {host}:{port}...")

            while True:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"Connected by {addr}")
                    try:
                        filename_length = int.from_bytes(conn.recv(4), 'big') #Get file size in order to send the file name only to the receiver, before sending full file
                        filename = conn.recv(filename_length).decode()
                        with open(filename, 'wb') as file:
                            while True:
                                data = conn.recv(buffer_size)
                                if not data:
                                    break
                                file.write(data)
                        time.sleep(0.3)
                        self.add_text(f"Received {filename}", is_user_message=False)
                        print(f"File {filename} has been received from {addr}")
                    except Exception as e:
                        print(f"Error receiving file: {e}")

    def tcp_client(self):
        buffer_size = 65536 #64kB

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                client_socket.connect((self.target_host, 50001))
                filename = self.file_selected.split('/')[-1].split(' ')[0] #Get the filename without the path
                filename_bytes = filename.encode()
                filename_length = len(filename_bytes)

                client_socket.sendall(filename_length.to_bytes(4, 'big')) #Send file name
                client_socket.sendall(filename_bytes) #Send file

                # Send the file content
                with open(self.file_selected, 'rb') as file:
                    while True:
                        bytes_read = file.read(buffer_size)
                        if not bytes_read:
                            break
                        client_socket.sendall(bytes_read)

                self.add_text(f"Sent {filename}", is_user_message=True)
                self.file_selected = ''
                print(f"File {self.file_selected} has been sent to {self.target_host}")

            except ConnectionRefusedError:
                print(f"Connection to {self.target_host} failed.")
            except FileNotFoundError:
                print("The file path provided does not exist.")
            except Exception as e:
                print(f"An error occurred: {e}")


    def add_text(self, text, is_user_message=False):
        self.text_area.config(state='normal')
        if is_user_message:
            self.text_area.insert(tk.END, text + '\n', 'right') #To the right if sent
        else:
            self.text_area.insert(tk.END, text + '\n', 'left') #To the left if received
        self.text_area.config(state='disabled')
        self.text_area.see(tk.END)


    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.message_entry.delete(0, tk.END)
            msg = Message(message, self.seq_num) #new object with the string message and the sequence number
            data = pickle.dumps(msg) #Serialize to send object
            self.sock.sendto(data, (self.target_host, self.target_port))
            self.messages_sent.append((msg, self.seq_num))
            timer = threading.Timer(4.0, lambda: self.handle_resend())#Set timeout (We chose 4 seconds)
            timer.start()
            self.message_timers[self.seq_num] = timer #Set timers to be removed later upon receiving ACK
            self.add_text(f"{message} <", is_user_message=True)
            self.text_area.insert(tk.END, '✓', 'check')
            self.text_area.insert(tk.END, '\n')
            self.correct_sent.append(message)
            self.seq_num += 1

    def receive(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            received_object = pickle.loads(data)
            if isinstance(received_object, Message):
                print(f"Received: {received_object.get_message()} with seq_num: {received_object.get_seq_num()}")
                if self.expected_seq_num == received_object.get_seq_num() - 1: #If this is the ack succeeding the last, ACK
                    self.correct_messages.append(received_object.get_message()) #Correctly ACKed (i.e. for the first time), store in correct messages
                    self.add_text(f"> {received_object.get_message()}") #Since correct, display in GUI
                    self.expected_seq_num += 1 #Increase expected seq_num to ACK next received message
                ack = ACK(self.expected_seq_num)
                self.sock.sendto(pickle.dumps(ack), addr)
                print(f"Sent ACK {ack.get_ack_num()} to {addr}")
            elif isinstance(received_object, ACK): # 2 types of ACKs, Message ACK, and Check In ACK
                if received_object.get_ack_type() == 'checkIn':
                    self.stopCheckInTimer()
                    print(f"Received check-in ACK from {addr}. State synchronized.") #Synchronized ==> Reset variables
                    self.messages_sent = []
                    self.correct_messages = []
                    self.acks_received = {}
                    self.correct_sent = []
                    self.message_timers = {}
                    self.expected_seq_num = 0
                    self.seq_num = 1
                    self.file_selected = ''
                else:
                    ack_num = received_object.get_ack_num()
                    print(f"Received ACK {ack_num}")
                    if ack_num in self.message_timers: # Received ACK for message, remove timeout for that message.
                        self.message_timers[ack_num].cancel()
                        del self.message_timers[ack_num]
                    if ack_num not in self.acks_received:
                        self.acks_received[ack_num] = 0
                    self.acks_received[ack_num] += 1
                    if self.acks_received[ack_num] == 3 or ack_num in self.message_timers: # 3 duplicate ACKs or timeout, retransmit all unacked messages with seq_num > last_acked
                        self.handle_resend()
                    if self.messages_sent and self.messages_sent[0][1] == ack_num: #Acked ==> remove it from messages_sent (it will be the first element)
                        self.messages_sent.pop(0)
            elif isinstance(received_object, checkIn):
                print("Received check-in from peer. Handling potential duplicates.")
                if not self.last_check_in_ack_sent or time.time() - self.last_check_in_ack_sent > 10:
                    current_state = ACK(self.expected_seq_num, ack_type='checkIn')
                    self.sock.sendto(pickle.dumps(current_state), addr)
                    self.last_check_in_ack_sent = time.time()
                    print(f"Sent current state as ACK {self.expected_seq_num} to peer.") #Received check in, send ack and reinitialize
                    self.messages_sent = []
                    self.correct_messages = []
                    self.acks_received = {}
                    self.correct_sent = []
                    self.message_timers = {}
                    self.expected_seq_num = 0
                    self.seq_num = 1
                    self.file_selected = ''


    def handle_resend(self):
        while len(self.messages_sent) > 0: #While there are still messages that need retransmitting, loop through them and send them, waiting for an ACK for each, or at least the last element
            last_ack_seq = max(self.acks_received.keys(), default=0)
            recv = threading.Thread(target=self.receive, daemon=True)
            recv.start()
            self.messages_sent = [message for message in self.messages_sent if message[1] > last_ack_seq] #Remove messages that have not been ACKed but their successors have been ACKed. This means the receiver had received them successfully
            print("messages sent: ", self.messages_sent)
            for message in self.messages_sent:
                print(f"Resending message with seq_num: {message[1]} due to triple duplicate ACKs or timeout")
                self.sock.sendto(pickle.dumps(message[0]), (self.target_host, self.target_port))
                time.sleep(1) # To not overflow the receiver
            recv.join() # Terminate receiver thread for each loop
            print("ACKS Received: ", self.acks_received)

def main():
    root = tk.Tk()
    root.geometry('400x800')
    app = ChatApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
