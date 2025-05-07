import tkinter as tk
from tkinter import scrolledtext


class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Chat App")
        self.geometry("900x600")
        self.resizable(False, False)
        self.configure(bg="#e8f0fe")

        self.container = tk.Frame(self, bg="#e8f0fe")
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (HomeScreen, LoginScreen, SignupScreen, ChatScreen):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(HomeScreen)

    def show_frame(self, frame_class):
        self.frames[frame_class].tkraise()


def add_placeholder(entry, placeholder_text):
    def on_focus_in(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg="#1a1a1a", show="*" if "password" in placeholder_text.lower() else "")

    def on_focus_out(event):
        if not entry.get():
            entry.insert(0, placeholder_text)
            entry.config(fg="gray", show="")

    entry.insert(0, placeholder_text)
    entry.config(fg="gray")
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)


class CenteredFrame(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#e8f0fe")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.inner_frame = tk.Frame(self, bg="#e8f0fe")
        self.inner_frame.grid(row=0, column=0)
        self.inner_frame.bind("<Configure>", self._center_inner)

    def _center_inner(self, event):
        self.inner_frame.update_idletasks()
        self.inner_frame.place(relx=0.5, rely=0.5, anchor="center")


class HomeScreen(CenteredFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        tk.Label(self.inner_frame, text="🔐 Secure Chat", font=("Helvetica", 32, "bold"), bg="#e8f0fe",
                 fg="#1a1a1a").pack(pady=40)

        tk.Button(self.inner_frame, text="Login", font=("Helvetica", 16), width=20, bg="#4a90e2", fg="white",
                  command=lambda: controller.show_frame(LoginScreen)).pack(pady=15)

        tk.Button(self.inner_frame, text="Sign Up", font=("Helvetica", 16), width=20, bg="#4a90e2", fg="white",
                  command=lambda: controller.show_frame(SignupScreen)).pack(pady=15)


class LoginScreen(CenteredFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        tk.Label(self.inner_frame, text="Login", font=("Helvetica", 28, "bold"), bg="#e8f0fe", fg="#1a1a1a").pack(
            pady=30)

        self.username = tk.Entry(self.inner_frame, width=35, font=("Helvetica", 14))
        self.username.pack(pady=10)
        add_placeholder(self.username, "Enter Username")

        self.password = tk.Entry(self.inner_frame, width=35, font=("Helvetica", 14))
        self.password.pack(pady=10)
        add_placeholder(self.password, "Enter Password")

        self.status_label = tk.Label(self.inner_frame, text="", font=("Helvetica", 12), fg="red", bg="#e8f0fe")
        self.status_label.pack(pady=(0, 10))

        tk.Button(self.inner_frame, text="Submit", font=("Helvetica", 14), width=15, bg="#4a90e2", fg="white",
                  command=lambda: self.login(controller)).pack(pady=10)

    def get_username(self):
        value = self.username.get()
        return value if value != "Enter Username" else ""

    def get_password(self):
        value = self.password.get()
        return value if value != "Enter Password" else ""

    @staticmethod
    def validate_login(username, password):
        # Placeholder for real DB check
        return True  # Change to real validation later

    def login(self, controller):
        username = self.get_username()
        password = self.get_password()

        if self.validate_login(username, password):
            print("Login - Username:", username)
            print("Login - Password:", password)
            self.status_label.config(text="")  # Clear any previous errors
            controller.show_frame(ChatScreen)
        else:
            self.status_label.config(text="Invalid username or password")


class SignupScreen(CenteredFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        tk.Label(self.inner_frame, text="Sign Up", font=("Helvetica", 28, "bold"), bg="#e8f0fe", fg="#1a1a1a").pack(
            pady=30)

        self.new_username = tk.Entry(self.inner_frame, width=35, font=("Helvetica", 14))
        self.new_username.pack(pady=10)
        add_placeholder(self.new_username, "Choose a Username")

        self.new_password = tk.Entry(self.inner_frame, width=35, font=("Helvetica", 14))
        self.new_password.pack(pady=10)
        add_placeholder(self.new_password, "Choose a Password")

        self.status_label = tk.Label(self.inner_frame, text="", font=("Helvetica", 12), fg="red", bg="#e8f0fe")
        self.status_label.pack(pady=(0, 10))

        tk.Button(self.inner_frame, text="Register", font=("Helvetica", 14), width=15, bg="#4a90e2", fg="white",
                  command=lambda: self.signup(controller)).pack(pady=10)

    def get_new_username(self):
        value = self.new_username.get()
        return value if value != "Choose a Username" else ""

    def get_new_password(self):
        value = self.new_password.get()
        return value if value != "Choose a Password" else ""

    @staticmethod
    def validate_signup(username, password):
        # Placeholder for real DB check (e.g., check if user already exists)
        return True  # Change to real validation later

    def signup(self, controller):
        username = self.get_new_username()
        password = self.get_new_password()

        if self.validate_signup(username, password):
            print("Signup - Username:", username)
            print("Signup - Password:", password)
            self.status_label.config(text="")  # Clear any previous errors
            controller.show_frame(ChatScreen)
        else:
            self.status_label.config(text="Username already exists or invalid input")


class ChatScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f0fe")
        self.controller = controller
        self.active_users = []

        self.left_frame = tk.Frame(self, bg="#d0e0f0", width=200)
        self.left_frame.pack(side="left", fill="y")

        tk.Label(self.left_frame, text="Active Users", font=("Helvetica", 14, "bold"), bg="#d0e0f0").pack(pady=10)
        self.users_listbox = tk.Listbox(self.left_frame, font=("Helvetica", 12), width=25, height=30)
        self.users_listbox.pack(padx=10, pady=10)

        self.chat_frame = tk.Frame(self, bg="#e8f0fe")
        self.chat_frame.pack(side="right", fill="both", expand=True)

        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, font=("Helvetica", 12), wrap=tk.WORD,
                                                      state="disabled")
        self.chat_display.pack(padx=10, pady=10, fill="both", expand=True)

        self.message_entry = tk.Entry(self.chat_frame, font=("Helvetica", 12))
        self.message_entry.pack(padx=10, pady=(0, 10), fill="x", side="left", expand=True)

        self.send_button = tk.Button(self.chat_frame, text="Send", font=("Helvetica", 12), bg="#4a90e2", fg="white",
                                     command=self.send_message)
        self.send_button.pack(padx=10, pady=(0, 10), side="right")

        tk.Button(self.chat_frame, text="Back to Home", font=("Helvetica", 10),
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=5)

    def display_system_message(self, message: str, color: str):
        self.chat_display.configure(state="normal")
        self.chat_display.insert(tk.END, message + "\n", ("system", color))
        self.chat_display.tag_config("green", foreground="green")
        self.chat_display.tag_config("red", foreground="red")
        self.chat_display.configure(state="disabled")
        self.chat_display.yview(tk.END)

    def send_message(self):
        message = self.message_entry.get()
        if message:
            self.chat_display.configure(state="normal")
            self.chat_display.insert(tk.END, f"You: {message}\n")
            self.chat_display.configure(state="disabled")
            self.message_entry.delete(0, tk.END)

    def add_active_user(self, username: str):
        if username not in self.active_users:
            self.active_users.append(username)
            self.users_listbox.insert(tk.END, username)
            self.display_system_message(f"{username} joined the chat.", "green")
            print(f"[INFO] Added user: {username}")

    def receive_message(self, sender: str, message: str):
        self.chat_display.configure(state="normal")
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.yview(tk.END)  # Auto-scroll
        print(f"[MESSAGE] {sender}: {message}")

    def remove_active_user(self, username: str):
        if username in self.active_users:
            self.active_users.remove(username)
            index = self.users_listbox.get(0, tk.END).index(username)
            self.users_listbox.delete(index)
            self.display_system_message(f"{username} disconnected.", "red")
            print(f"[INFO] Removed user: {username}")


if __name__ == "__main__":
    app = ChatApp()
    app.after(3000, lambda: app.frames[ChatScreen].add_active_user("alice"))
    app.after(6000, lambda: app.frames[ChatScreen].receive_message("alice", "Hey everyone!"))
    app.after(12000, lambda: app.frames[ChatScreen].remove_active_user("alice"))
    app.mainloop()
