import tkinter as tk
from tkinter import filedialog, messagebox
import PyPDF2
import os

class PDFDecryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Decryptor")
        
        
        tk.Label(root, text="Encrypted PDF File:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.pdf_file_entry = tk.Entry(root, width=50)
        self.pdf_file_entry.grid(row=0, column=1, padx=10, pady=10)
        tk.Button(root, text="Browse", command=self.browse_pdf_file).grid(row=0, column=2, padx=10, pady=10)
        
        tk.Label(root, text="Password List File:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.password_file_entry = tk.Entry(root, width=50)
        self.password_file_entry.grid(row=1, column=1, padx=10, pady=10)
        tk.Button(root, text="Browse", command=self.browse_password_file).grid(row=1, column=2, padx=10, pady=10)
        
        tk.Label(root, text="Output PDF File:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.output_file_entry = tk.Entry(root, width=50)
        self.output_file_entry.grid(row=2, column=1, padx=10, pady=10)
        tk.Button(root, text="Browse", command=self.browse_output_file).grid(row=2, column=2, padx=10, pady=10)
        
        tk.Button(root, text="Decrypt PDF", command=self.decrypt_pdf).grid(row=3, column=0, columnspan=3, pady=20)
    
    def browse_pdf_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        self.pdf_file_entry.delete(0, tk.END)
        self.pdf_file_entry.insert(0, file_path)
    
    def browse_password_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.password_file_entry.delete(0, tk.END)
        self.password_file_entry.insert(0, file_path)
    
    def browse_output_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        self.output_file_entry.delete(0, tk.END)
        self.output_file_entry.insert(0, file_path)
    
    def open_pdf_with_password(self, pdf_file, password):
        try:
            with open(pdf_file, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                if reader.is_encrypted:
                    if reader.decrypt(password):
                        return True
                return False
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            return False
    
    def brute_force_pdf(self, pdf_file, password_list):
        for password in password_list:
            password = password.strip()
            if self.open_pdf_with_password(pdf_file, password):
                return password
        return None
    
    def save_decrypted_pdf(self, input_pdf, output_pdf, password):
        try:
            with open(input_pdf, 'rb') as file:
                reader = PyPDF2.PdfReader(file)
                reader.decrypt(password)
                
                writer = PyPDF2.PdfWriter()
                for page_num in range(len(reader.pages)):
                    writer.add_page(reader.pages[page_num])
                
                with open(output_pdf, 'wb') as output_file:
                    writer.write(output_file)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving the PDF: {e}")
    
    def decrypt_pdf(self):
        pdf_file = self.pdf_file_entry.get()
        password_file = self.password_file_entry.get()
        output_pdf = self.output_file_entry.get()
        
        if not (pdf_file and password_file and output_pdf):
            messagebox.showwarning("Input Error", "Please provide all file paths.")
            return
        
        if not os.path.isfile(pdf_file):
            messagebox.showerror("File Error", "Encrypted PDF file not found.")
            return
        
        if not os.path.isfile(password_file):
            messagebox.showerror("File Error", "Password list file not found.")
            return
        
        try:
            with open(password_file, 'r') as file:
                password_list = file.readlines()
            
            found_password = self.brute_force_pdf(pdf_file, password_list)
            
            if found_password:
                self.save_decrypted_pdf(pdf_file, output_pdf, found_password)
                messagebox.showinfo("Success", f"PDF decrypted successfully with password: {found_password}")
            else:
                messagebox.showinfo("Failure", "No valid password found.")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFDecryptorApp(root)
    root.mainloop()