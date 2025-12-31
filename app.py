import customtkinter as ctk
from tkinter import messagebox
import re
import hashlib
import secrets
import string
import json
from datetime import datetime

# Set appearance mode
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Constants
MIN_PASSWORD_LENGTH = 8
STRONG_PASSWORD_LENGTH = 12

class PasswordStrengthChecker:
    def __init__(self):
        self.app = ctk.CTk()
        self.setup_window()
        self.setup_ui()
        
    def setup_window(self):
        """Configure main window"""
        self.app.title("🔐 Password Strength Analyzer")
        self.app.geometry("520x700")
        self.app.minsize(480, 650)
        
    def setup_ui(self):
        """Setup user interface"""
        # Custom font settings
        self.title_font = ("Arial", 24, "bold")
        self.subtitle_font = ("Arial", 12)
        self.heading_font = ("Arial", 14, "bold")
        self.body_font = ("Arial", 11)
        self.button_font = ("Arial", 12, "bold")
        self.small_font = ("Arial", 10)
        
        # Main container
        self.main_frame = ctk.CTkFrame(self.app, corner_radius=15)
        self.main_frame.pack(padx=25, pady=25, fill="both", expand=True)
        
        # Title section
        self.create_title_section()
        
        # Password input section
        self.create_input_section()
        
        # Strength indicator
        self.create_strength_indicator()
        
        # Requirements section
        self.create_requirements_section()
        
        # Suggestions section
        self.create_suggestions_section()
        
        # Buttons section
        self.create_buttons_section()
        
        # Footer
        self.create_footer()
        
        # Initialize variables
        self.password_var = ctk.StringVar()
        
        # Bind events
        self.password_entry.bind("<KeyRelease>", self.on_password_change)
    
    def create_title_section(self):
        """Create title section"""
        title_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        title_frame.pack(pady=(20, 15), padx=20, fill="x")
        
        # Title
        title_label = ctk.CTkLabel(
            title_frame,
            text="Password Strength Analyzer",
            font=self.title_font,
            text_color="#FFFFFF"
        )
        title_label.pack()
        
        # Subtitle
        subtitle_label = ctk.CTkLabel(
            title_frame,
            text="Evaluate and enhance your password security",
            font=self.subtitle_font,
            text_color="#A0A0A0"
        )
        subtitle_label.pack(pady=(8, 0))
        
        # Divider line
        divider = ctk.CTkFrame(
            title_frame,
            height=2,
            fg_color="#2A2A2A"
        )
        divider.pack(fill="x", pady=(15, 0))
    
    def create_input_section(self):
        """Create password input section"""
        input_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        input_frame.pack(pady=(10, 15), padx=20, fill="x")
        
        # Label
        ctk.CTkLabel(
            input_frame,
            text="ENTER YOUR PASSWORD",
            font=self.heading_font,
            text_color="#E0E0E0"
        ).pack(anchor="w", pady=(0, 10))
        
        # Entry field and buttons container
        entry_container = ctk.CTkFrame(input_frame, fg_color="transparent")
        entry_container.pack(fill="x")
        
        # Entry widget
        self.password_entry = ctk.CTkEntry(
            entry_container,
            show="•",
            placeholder_text="Type or paste password here...",
            height=45,
            font=("Arial", 13),
            corner_radius=8,
            border_width=2,
            border_color="#3A3A3A",
            fg_color="#1E1E1E"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Action buttons container
        action_frame = ctk.CTkFrame(entry_container, fg_color="transparent")
        action_frame.pack(side="right")
        
        # Show/Hide button
        self.show_btn = ctk.CTkButton(
            action_frame,
            text="👁 Show",
            width=90,
            height=35,
            command=self.toggle_show,
            font=self.body_font,
            corner_radius=6,
            fg_color="#2D5AA0",
            hover_color="#1E4A8A"
        )
        self.show_btn.pack(side="left", padx=(0, 8))
        
        # Generate button
        self.generate_btn = ctk.CTkButton(
            action_frame,
            text="🎲 Generate",
            width=100,
            height=35,
            command=self.generate_password,
            font=self.body_font,
            corner_radius=6,
            fg_color="#5A2D8C",
            hover_color="#4A1E7A"
        )
        self.generate_btn.pack(side="left")
    
    def create_strength_indicator(self):
        """Create strength indicator section"""
        strength_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        strength_frame.pack(pady=(10, 15), padx=20, fill="x")
        
        # Header
        header_frame = ctk.CTkFrame(strength_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 10))
        
        # Strength label
        self.strength_text = ctk.CTkLabel(
            header_frame,
            text="STRENGTH: NOT EVALUATED",
            font=self.heading_font,
            text_color="#B0B0B0"
        )
        self.strength_text.pack(side="left")
        
        # Score label
        self.score_label = ctk.CTkLabel(
            header_frame,
            text="",
            font=self.body_font,
            text_color="#808080"
        )
        self.score_label.pack(side="right")
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            strength_frame,
            height=22,
            corner_radius=11,
            progress_color="#404040",
            fg_color="#1E1E1E",
            border_width=1,
            border_color="#3A3A3A"
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x")
        
        # Strength description
        self.strength_desc = ctk.CTkLabel(
            strength_frame,
            text="Enter a password to begin analysis",
            font=self.body_font,
            text_color="#808080"
        )
        self.strength_desc.pack(pady=(8, 0))
    
    def create_requirements_section(self):
        """Create requirements checklist"""
        req_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        req_frame.pack(pady=(10, 15), padx=20, fill="x")
        
        # Title
        ctk.CTkLabel(
            req_frame,
            text="PASSWORD REQUIREMENTS",
            font=self.heading_font,
            text_color="#E0E0E0"
        ).pack(anchor="w", pady=(0, 12))
        
        # Requirements grid (2 columns)
        grid_frame = ctk.CTkFrame(req_frame, fg_color="transparent")
        grid_frame.pack(fill="x")
        
        # Left column
        left_col = ctk.CTkFrame(grid_frame, fg_color="transparent")
        left_col.pack(side="left", fill="both", expand=True)
        
        # Right column
        right_col = ctk.CTkFrame(grid_frame, fg_color="transparent")
        right_col.pack(side="right", fill="both", expand=True)
        
        # Requirements list
        self.requirements = {}
        req_items = [
            ("length", "At least 8 characters", left_col),
            ("length_strong", "12+ characters (ideal)", right_col),
            ("uppercase", "Uppercase letter (A-Z)", left_col),
            ("lowercase", "Lowercase letter (a-z)", right_col),
            ("digit", "Number (0-9)", left_col),
            ("special", "Special character (!@#$)", right_col)
        ]
        
        for key, text, column in req_items:
            req_item = ctk.CTkFrame(column, fg_color="transparent")
            req_item.pack(anchor="w", pady=(0, 8))
            
            # Status indicator
            status = ctk.CTkLabel(
                req_item,
                text="○",
                font=("Arial", 12),
                text_color="#808080",
                width=20
            )
            status.pack(side="left", padx=(0, 8))
            
            # Requirement text
            text_label = ctk.CTkLabel(
                req_item,
                text=text,
                font=self.body_font,
                text_color="#A0A0A0"
            )
            text_label.pack(side="left")
            
            self.requirements[key] = (status, text_label)
    
    def create_suggestions_section(self):
        """Create suggestions section"""
        suggestions_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        suggestions_frame.pack(pady=(10, 15), padx=20, fill="both", expand=True)
        
        # Title
        ctk.CTkLabel(
            suggestions_frame,
            text="SUGGESTIONS & FEEDBACK",
            font=self.heading_font,
            text_color="#E0E0E0"
        ).pack(anchor="w", pady=(0, 10))
        
        # Textbox for suggestions (simpler approach)
        self.suggestions_box = ctk.CTkTextbox(
            suggestions_frame,
            height=100,
            font=self.body_font,
            corner_radius=8,
            border_width=2,
            border_color="#3A3A3A",
            fg_color="#1E1E1E",
            text_color="#D0D0D0"
        )
        self.suggestions_box.pack(fill="both", expand=True)
        
        # Make it read-only by binding events
        self.make_textbox_readonly()
        
        # Set initial message
        self.suggestions_box.insert("1.0", "Enter a password and click 'Check Strength' to see suggestions.\n\n")
        self.suggestions_box.insert("end", "This box is read-only. Suggestions will appear here automatically.")
        self.suggestions_box.configure(state="disabled")
    
    def make_textbox_readonly(self):
        """Make textbox read-only by binding events"""
        def block_event(event):
            # Allow only Ctrl+C for copy and navigation keys
            if event.state & 0x4 and event.keysym.lower() == 'c':  # Ctrl+C
                return
            if event.keysym in ['Left', 'Right', 'Up', 'Down', 'Home', 'End', 
                              'Prior', 'Next', 'Control_L', 'Control_R']:
                return
            return "break"
        
        # Bind events to prevent editing
        self.suggestions_box.bind("<Key>", block_event)
        self.suggestions_box.bind("<BackSpace>", lambda e: "break")
        self.suggestions_box.bind("<Delete>", lambda e: "break")
        self.suggestions_box.bind("<Button-1>", lambda e: "break")  # Prevent clicking
    
    def create_buttons_section(self):
        """Create action buttons"""
        button_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        button_frame.pack(pady=(10, 15), padx=20)
        
        # Left side buttons
        left_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        left_buttons.pack(side="left")
        
        # Check Strength button
        self.check_btn = ctk.CTkButton(
            left_buttons,
            text="🔍 Check Strength",
            command=self.check_strength,
            height=42,
            width=160,
            font=self.button_font,
            corner_radius=8,
            fg_color="#2D5AA0",
            hover_color="#1E4A8A"
        )
        self.check_btn.pack(side="left", padx=(0, 12))
        
        # Copy button
        self.copy_btn = ctk.CTkButton(
            left_buttons,
            text="📋 Copy",
            command=self.copy_password,
            height=42,
            width=100,
            font=self.button_font,
            corner_radius=8,
            fg_color="#5A8C2D",
            hover_color="#4A7A1E",
            state="disabled"
        )
        self.copy_btn.pack(side="left")
        
        # Right side - Save checkbox
        right_buttons = ctk.CTkFrame(button_frame, fg_color="transparent")
        right_buttons.pack(side="right")
        
        self.save_var = ctk.BooleanVar(value=False)
        self.save_checkbox = ctk.CTkCheckBox(
            right_buttons,
            text="💾 Save Securely",
            variable=self.save_var,
            font=self.body_font,
            text_color="#A0A0A0"
        )
        self.save_checkbox.pack(side="right", padx=(10, 0))
    
    def create_footer(self):
        """Create footer with tips"""
        footer_frame = ctk.CTkFrame(
            self.main_frame,
            height=28,
            fg_color="#1A1A1A",
            corner_radius=0
        )
        footer_frame.pack(side="bottom", fill="x", padx=0, pady=0)
        
        tip_label = ctk.CTkLabel(
            footer_frame,
            text="💡 Tip: Strong passwords use 12+ characters with uppercase, lowercase, numbers, and symbols",
            font=self.small_font,
            text_color="#707070"
        )
        tip_label.pack(pady=6)
    
    def toggle_show(self):
        """Toggle password visibility"""
        if self.password_entry.cget("show") == "•":
            self.password_entry.configure(show="")
            self.show_btn.configure(text="🙈 Hide")
        else:
            self.password_entry.configure(show="•")
            self.show_btn.configure(text="👁 Show")
    
    def generate_password(self):
        """Generate a strong password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(16))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*" for c in password)):
                break
        
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        
        # Update UI
        self.on_password_change()
        messagebox.showinfo("Password Generated", 
                          "A strong password has been generated!")
    
    def on_password_change(self, event=None):
        """Handle real-time password changes"""
        password = self.password_entry.get()
        
        # Enable/disable copy button
        self.copy_btn.configure(state="normal" if password else "disabled")
        
        # Update requirements in real-time
        self.update_requirements_real_time(password)
    
    def update_requirements_real_time(self, password):
        """Update requirements checklist in real-time"""
        if not password:
            # Reset all to default
            for key, (status, text_label) in self.requirements.items():
                status.configure(text="○", text_color="#808080")
                text_label.configure(text_color="#A0A0A0")
            return
        
        # Update each requirement
        checks = [
            ('length', len(password) >= MIN_PASSWORD_LENGTH),
            ('length_strong', len(password) >= STRONG_PASSWORD_LENGTH),
            ('uppercase', bool(re.search(r'[A-Z]', password))),
            ('lowercase', bool(re.search(r'[a-z]', password))),
            ('digit', bool(re.search(r'\d', password))),
            ('special', bool(re.search(r'[!@#$%^&*]', password)))
        ]
        
        for key, condition in checks:
            status, text_label = self.requirements[key]
            if condition:
                status.configure(text="✓", text_color="#4CAF50")
                text_label.configure(text_color="#D0D0D0")
            else:
                status.configure(text="✗", text_color="#F44336")
                text_label.configure(text_color="#808080")
    
    def check_strength(self):
        """Check password strength"""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("No Password", 
                                 "Please enter a password to check its strength.")
            return
        
        # Calculate score
        score = 0
        feedback = []
        
        # Length scoring
        if len(password) >= 16:
            score += 3
            feedback.append("✅ Excellent length (16+ characters)")
        elif len(password) >= 12:
            score += 2
            feedback.append("✅ Good length (12+ characters)")
        elif len(password) >= 8:
            score += 1
            feedback.append("✅ Minimum length met (8+ characters)")
        else:
            feedback.append("❌ Password should be at least 8 characters long")
        
        # Character type checks
        char_checks = [
            (r'[A-Z]', "uppercase letters"),
            (r'[a-z]', "lowercase letters"),
            (r'\d', "numbers"),
            (r'[!@#$%^&*]', "special characters")
        ]
        
        for pattern, name in char_checks:
            if re.search(pattern, password):
                score += 1
                feedback.append(f"✅ Contains {name}")
            else:
                feedback.append(f"❌ Needs {name}")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):  # 3 or more repeated chars
            score = max(0, score - 1)
            feedback.append("⚠ Avoid repeated characters (like 'aaa' or '111')")
        
        # Check for sequential patterns
        if re.search(r'(123|234|345|456|567|678|789|abc|bcd|cde|def|efg)', password.lower()):
            feedback.append("⚠ Avoid sequential patterns")
        
        # Check for common passwords
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome", 
                           "password123", "12345678", "123456789", "letmein"]
        if password.lower() in common_passwords:
            feedback.insert(0, "🚨 CRITICAL: This is a commonly hacked password!")
            feedback.insert(1, "🚨 Change this password immediately!")
        
        # Calculate percentage
        max_score = 7
        percentage = min(100, (score / max_score) * 100)
        
        # Determine strength level
        if percentage < 30:
            strength = "VERY WEAK"
            color = "#FF5252"
            desc = "Highly vulnerable to attacks"
        elif percentage < 50:
            strength = "WEAK"
            color = "#FF9800"
            desc = "Needs significant improvement"
        elif percentage < 70:
            strength = "MODERATE"
            color = "#FFEB3B"
            desc = "Acceptable but could be better"
        elif percentage < 85:
            strength = "STRONG"
            color = "#4CAF50"
            desc = "Good security level"
        elif percentage < 95:
            strength = "VERY STRONG"
            color = "#2196F3"
            desc = "Excellent protection"
        else:
            strength = "EXCELLENT"
            color = "#9C27B0"
            desc = "Maximum security achieved"
        
        # Update UI - strength indicator
        self.progress_bar.set(percentage / 100)
        self.progress_bar.configure(progress_color=color)
        
        self.strength_text.configure(
            text=f"STRENGTH: {strength}",
            text_color=color
        )
        
        self.strength_desc.configure(
            text=desc,
            text_color=color
        )
        
        self.score_label.configure(
            text=f"Score: {score}/7 • {percentage:.1f}% • Length: {len(password)}"
        )
        
        # Update suggestions box
        self.suggestions_box.configure(state="normal")
        self.suggestions_box.delete("1.0", "end")
        
        # Add results with simple formatting
        self.suggestions_box.insert("end", "🔍 PASSWORD ANALYSIS RESULTS\n")
        self.suggestions_box.insert("end", "=" * 40 + "\n\n")
        
        for item in feedback:
            self.suggestions_box.insert("end", f"{item}\n")
        
        self.suggestions_box.insert("end", "\n" + "=" * 40 + "\n")
        if percentage >= 70:
            self.suggestions_box.insert("end", "🎉 Your password is secure!\n")
        else:
            self.suggestions_box.insert("end", "💡 Follow suggestions above to improve\n")
        
        # Make it read-only again
        self.suggestions_box.configure(state="disabled")
        
        # Save if requested
        if self.save_var.get():
            self.save_analysis(password, strength, score, percentage)
    
    def save_analysis(self, password, strength, score, percentage):
        """Save password analysis"""
        try:
            hashed = hashlib.sha256(password.encode()).hexdigest()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            save_data = {
                'timestamp': timestamp,
                'strength': strength,
                'score': score,
                'percentage': percentage,
                'hash': hashed[:16] + "..."
            }
            
            try:
                with open("password_history.json", "r") as f:
                    history = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                history = []
            
            history.append(save_data)
            
            # Keep only last 50 entries
            if len(history) > 50:
                history = history[-50:]
            
            with open("password_history.json", "w") as f:
                json.dump(history, f, indent=2)
            
            messagebox.showinfo("Saved", 
                              f"Analysis saved successfully!\n\nStrength: {strength}\nScore: {score}/7 ({percentage:.1f}%)")
        except Exception as e:
            messagebox.showerror("Save Error", 
                               f"Could not save analysis:\n{str(e)}")
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_entry.get()
        if password:
            try:
                self.app.clipboard_clear()
                self.app.clipboard_append(password)
                
                # Visual feedback
                original_text = self.copy_btn.cget("text")
                self.copy_btn.configure(
                    text="✓ Copied!",
                    fg_color="#4CAF50",
                    hover_color="#45A049"
                )
                
                # Restore after delay
                def restore_button():
                    self.copy_btn.configure(
                        text=original_text,
                        fg_color="#5A8C2D",
                        hover_color="#4A7A1E"
                    )
                
                self.app.after(2000, restore_button)
                
            except Exception as e:
                messagebox.showerror("Copy Failed", 
                                   f"Could not copy to clipboard:\n{str(e)}")
    
    def run(self):
        """Run the application"""
        self.app.mainloop()

def main():
    """Main entry point"""
    app = PasswordStrengthChecker()
    app.run()

if __name__ == "__main__":
    main()