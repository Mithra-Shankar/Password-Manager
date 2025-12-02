import tkinter as tk
from tkinter import ttk, messagebox
import os

# External logic files
import storage
import encryption
import password_logic


# ----------------------------- LOGIN SCREEN -----------------------------
def login_screen():
    win = tk.Tk()
    win.title("Master Access")
    win.geometry("450x300")
    win.configure(bg="#212121")
    win.resizable(False, False)

    card = tk.Frame(
        win,
        bg="#333333",
        padx=35,
        pady=35,
        relief="flat",
        bd=0
    )
    card.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(
        card,
        text="🔐 Master Password",
        font=("Arial", 20, "bold"),
        bg="#333333",
        fg="#E0E0E0"
    ).pack(pady=(5, 15))

    pwd_entry = tk.Entry(
        card,
        font=("Arial", 14),
        show="•",
        width=30,
        relief="flat",
        fg="#FFFFFF",
        bg="#424242",
        insertbackground="#FFFFFF",
        highlightbackground="#D32F2F",
        highlightcolor="#D32F2F",
        highlightthickness=1
    )
    pwd_entry.pack(pady=10, ipady=6)

    btn_frame = tk.Frame(card, bg="#333333")
    btn_frame.pack(pady=15)

    def styled_btn(parent, text, cmd):
        return tk.Button(
            parent,
            text=text,
            font=("Arial", 12, "bold"),
            fg="white",
            bg="#D32F2F",
            activebackground="#A02222",
            cursor="hand2",
            relief="flat",
            width=20,
            command=cmd
        )

    if not storage.master_exists():

        def create_master():
            p = pwd_entry.get()
            if len(p) < 4:
                messagebox.showerror("Error", "Password must be at least 4 characters.")
                return
            storage.create_master_password(p)
            messagebox.showinfo("Success", "Master Password Created!\nRestart App.")
            win.destroy()

        styled_btn(btn_frame, "Create Password", create_master).pack()

    else:

        def unlock():
            p = pwd_entry.get()
            if storage.verify_master_password(p):
                win.destroy()
                main_app()
            else:
                messagebox.showerror("Error", "Wrong Password.")

        styled_btn(btn_frame, "Unlock", unlock).pack()
        win.bind('<Return>', lambda event: unlock())

    win.mainloop()


# ----------------------------- MAIN APP -----------------------------
def main_app():
    root = tk.Tk()
    root.title("SecurePass Manager")
    root.geometry("1000x600")
    root.configure(bg="#F5F5F5")

    sidebar = tk.Frame(root, width=220, bg="#212121")
    sidebar.pack(side="left", fill="y")

    tk.Label(
        sidebar,
        text="SecurePass",
        font=("Arial", 18, "bold"),
        fg="#D32F2F",
        bg="#212121"
    ).pack(pady=(30, 15))

    content = tk.Frame(root, bg="#FFFFFF")
    content.pack(side="right", fill="both", expand=True)

    def clear_content():
        for w in content.winfo_children():
            w.destroy()

    def sidebar_button(text, command):
        btn = tk.Button(
            sidebar,
            text=f"  {text}",
            anchor="w",
            font=("Arial", 14),
            fg="#CCCCCC",
            bg="#212121",
            activebackground="#3A3A3A",
            activeforeground="white",
            bd=0,
            height=2,
            relief="flat",
            command=command
        )
        btn.pack(fill="x", pady=2)

    # ------------------- DASHBOARD -------------------
    def page_dashboard():
        clear_content()

        tk.Label(
            content,
            text="Dashboard Overview",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(40, 20))

        total = len(storage.get_all_entries())

        box = tk.Frame(content, bg="#F0F0F0", bd=0, relief="flat")
        box.pack(pady=30, ipadx=40, ipady=30)

        tk.Label(
            box,
            text="Total Saved Entries:",
            font=("Arial", 16),
            bg="#F0F0F0",
            fg="#555555"
        ).pack()

        tk.Label(
            box,
            text=f"🔑 {total}",
            font=("Arial", 36, "bold"),
            bg="#F0F0F0",
            fg="#D32F2F"
        ).pack(pady=(5, 0))

    # ------------------- ADD NEW -------------------
    def page_add():
        clear_content()

        tk.Label(
            content,
            text="➕ Add New Password",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(40, 20))

        form_container = tk.Frame(content, bg="#FFFFFF", padx=30, pady=20)
        form_container.pack(pady=10)

        def create_input(label_text):
            tk.Label(
                form_container,
                text=label_text,
                font=("Arial", 13, "bold"),
                bg="white",
                fg="#444444"
            ).pack(pady=(10, 2), anchor="w")

            entry = tk.Entry(
                form_container,
                width=45,
                font=("Arial", 14),
                bg="#F5F5F5",
                relief="flat"
            )
            entry.pack(pady=3, ipady=4)
            return entry

        entry_website = create_input("Website/Service:")
        entry_username = create_input("Username/Email:")

        tk.Label(
            form_container,
            text="Password:",
            font=("Arial", 13, "bold"),
            bg="white",
            fg="#444444"
        ).pack(pady=(10, 2), anchor="w")

        pass_frame = tk.Frame(form_container, bg="white")
        pass_frame.pack()

        entry_password = tk.Entry(
            pass_frame,
            width=32,
            font=("Arial", 14),
            bg="#F5F5F5",
            relief="flat"
        )
        entry_password.pack(side="left", padx=(0, 10), ipady=4)

        def copy_pwd():
            pwd = entry_password.get()
            if pwd == "":
                messagebox.showerror("Error", "No password to copy.")
                return
            root.clipboard_clear()
            root.clipboard_append(pwd)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

        tk.Button(
            pass_frame,
            text="Copy",
            bg="#D32F2F",
            fg="white",
            font=("Arial", 11, "bold"),
            relief="flat",
            command=copy_pwd
        ).pack(side="left")

        def generate_pwd():
            pwd = password_logic.generate_password(16)
            entry_password.delete(0, tk.END)
            entry_password.insert(0, pwd)

        tk.Button(
            form_container,
            text="Generate Strong Password",
            bg="#3A3A3A",
            fg="white",
            font=("Arial", 12, "bold"),
            pady=8,
            relief="flat",
            command=generate_pwd
        ).pack(pady=15, fill="x")

        def save_password():
            website = entry_website.get().strip()
            username = entry_username.get().strip()
            password = entry_password.get().strip()

            if not website or not username or not password:
                messagebox.showerror("Error", "All fields must be filled.")
                return

            enc = encryption.encrypt(password)
            storage.add_entry(website, username, enc)
            messagebox.showinfo("Saved", "Password Saved Successfully!")

            entry_website.delete(0, tk.END)
            entry_username.delete(0, tk.END)
            entry_password.delete(0, tk.END)

        tk.Button(
            form_container,
            text="Save Entry",
            bg="#1E88E5",
            fg="white",
            font=("Arial", 14, "bold"),
            pady=8,
            relief="flat",
            command=save_password
        ).pack(pady=(20, 10), fill="x")

    # ------------------- VIEW PASSWORDS (FAANG EDITION) -------------------
    def page_passwords():
        clear_content()

        tk.Label(
            content,
            text="🔑 Saved Passwords",
            font=("Arial", 28, "bold"),
            bg="white",
            fg="#222222"
        ).pack(pady=(30, 15))

        # Search bar
        search_var = tk.StringVar()
        search = tk.Entry(
            content,
            textvariable=search_var,
            font=("Arial", 14),
            bg="#EFEFEF",
            relief="flat",
            width=40
        )
        search.insert(0, "Search website or username")
        search.pack(pady=(5, 15))

        def clear_placeholder(e):
            if search.get().startswith("Search"):
                search.delete(0, tk.END)

        search.bind("<FocusIn>", clear_placeholder)
        search.bind("<KeyRelease>", lambda e: refresh_list())

        # TreeView table
        columns = ("id", "website", "username", "password")
        tree = ttk.Treeview(content, columns=columns, show="headings", height=14)

        tree.heading("id", text="ID")
        tree.heading("website", text="Website")
        tree.heading("username", text="Username")
        tree.heading("password", text="Password (masked)")

        tree.column("id", width=40, anchor="center")
        tree.column("website", width=240)
        tree.column("username", width=240)
        tree.column("password", width=260)

        tree.pack(fill="both", padx=20, pady=(0, 12))

        scrollbar = ttk.Scrollbar(content, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(in_=tree, relx=1.0, rely=0, relheight=1.0, bordermode="outside")

        def mask(p):
            if len(p) <= 10:
                return "*" * len(p)
            return "*" * 10 + "…"

        def refresh_list():
            for row in tree.get_children():
                tree.delete(row)

            q = search_var.get().lower().strip()
            if q.startswith("search"):
                q = ""

            for item in storage.get_all_entries():
                dec = encryption.decrypt(item["password"])
                if q and not (q in item["website"].lower() or q in item["username"].lower()):
                    continue

                tree.insert(
                    "",
                    "end",
                    values=(item["id"], item["website"], item["username"], mask(dec))
                )

        refresh_list()

        def get_selected():
            sel = tree.selection()
            if not sel:
                messagebox.showerror("Error", "Select an entry first.")
                return None
            vals = tree.item(sel[0])["values"]
            return {
                "id": vals[0],
                "website": vals[1],
                "username": vals[2]
            }

        # --- Buttons ---
        btn_frame = tk.Frame(content, bg="white")
        btn_frame.pack(pady=(5, 20))

        def reveal():
            s = get_selected()
            if not s:
                return
            for it in storage.get_all_entries():
                if it["id"] == s["id"]:
                    dec = encryption.decrypt(it["password"])
                    messagebox.showinfo(
                        "Password",
                        f"Website: {it['website']}\nUsername: {it['username']}\nPassword: {dec}"
                    )
                    return

        def copy_password():
            s = get_selected()
            if not s:
                return
            for it in storage.get_all_entries():
                if it["id"] == s["id"]:
                    dec = encryption.decrypt(it["password"])
                    root.clipboard_clear()
                    root.clipboard_append(dec)
                    messagebox.showinfo("Copied", "Password copied!")
                    return

        def copy_username():
            s = get_selected()
            if not s:
                return
            root.clipboard_clear()
            root.clipboard_append(s["username"])
            messagebox.showinfo("Copied", "Username copied!")

        def delete_selected():
            s = get_selected()
            if not s:
                return
            if not messagebox.askyesno("Confirm", "Delete entry permanently?"):
                return
            storage.delete_entry(s["id"])
            refresh_list()
            messagebox.showinfo("Deleted", "Entry deleted.")

        tk.Button(btn_frame, text="Reveal", bg="#2563EB", fg="white",
                  font=("Arial", 12, "bold"), relief="flat",
                  width=14, command=reveal).grid(row=0, column=0, padx=10)

        tk.Button(btn_frame, text="Copy Password", bg="#374151", fg="white",
                  font=("Arial", 12, "bold"), relief="flat",
                  width=15, command=copy_password).grid(row=0, column=1, padx=10)

        tk.Button(btn_frame, text="Copy Username", bg="#6B7280", fg="white",
                  font=("Arial", 12, "bold"), relief="flat",
                  width=15, command=copy_username).grid(row=0, column=2, padx=10)

        tk.Button(btn_frame, text="Delete", bg="#C53030", fg="white",
                  font=("Arial", 12, "bold"), relief="flat",
                  width=14, command=delete_selected).grid(row=0, column=3, padx=10)

    # Sidebar navigation
    sidebar_button("🏠 Dashboard", page_dashboard)
    sidebar_button("➕ Add New", page_add)
    sidebar_button("🔑 View Passwords", page_passwords)

    page_dashboard()
    root.mainloop()


# ----------------------------- RUN APP -----------------------------
login_screen()
