from django import forms
from .models import Order, Customer, Product, Admin, Category
from django.contrib.auth.models import User
from django.utils.text import slugify


class StockUpdateForm(forms.Form):
    stock_quantity = forms.IntegerField(label="Stock Quantity")


class CheckoutForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ["ordered_by", "shipping_address", "mobile", "email", "payment_method"]


class CustomerRegistrationForm(forms.ModelForm):
    password = forms.CharField(
        min_length=8, max_length=20, widget=forms.PasswordInput()
    )
    email = forms.CharField(widget=forms.EmailInput())

    class Meta:
        model = Customer
        fields = ["full_name", "image", "address", "mobile", "email", "password"]

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if Customer.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")
        return email

    def clean_mobile(self):
        mobile = self.cleaned_data.get("mobile")
        if self.instance._state.adding and Customer.objects.filter(mobile=mobile).exists():
            raise forms.ValidationError("Mobile number already exists.")
        return mobile

    def save(self, commit=True):
        customer = super().save(commit=False)
        
        # Generate username automatically
        full_name = self.cleaned_data.get("full_name")
        base_username = slugify(full_name)
        username = base_username
        counter = 1
        while Customer.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
        customer.username = username
        
        # Set hashed password
        customer.set_password(self.cleaned_data["password"])
        
        if commit:
            customer.save()
            
        return customer


class CustomerLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput())
    password = forms.CharField(widget=forms.PasswordInput())


class AdminRegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput())
    email = forms.CharField(widget=forms.EmailInput())

    class Meta:
        model = Admin
        fields = ["full_name", "image", "mobile", "email", "password"]

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")
        return email

    def clean_mobile(self):
        mobile = self.cleaned_data.get("mobile")
        if Admin.objects.filter(mobile=mobile).exists():
            raise forms.ValidationError("Mobile number already exists.")
        return mobile

    def save(self, commit=True):
        full_name = self.cleaned_data.get("full_name")
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        # Generate username from full_name or fallback to email
        base_username = slugify(full_name) if full_name else email.split("@")[0]
        if not base_username:
            raise forms.ValidationError("Cannot generate username automatically.")

        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        # Create the User
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        user.is_staff = True  # Make admin
        user.save()

        # Create Admin instance
        admin = super().save(commit=False)
        admin.user = user
        admin.username = username
        if commit:
            admin.save()

        return admin


class AdminProfileUpdateForm(forms.ModelForm):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "autocomplete": "new-password"}),
        required=False,
        label="New Password",
        help_text="Leave blank if you don't want to change it."
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "autocomplete": "new-password"}),
        required=False,
        label="Confirm New Password"
    )

    class Meta:
        model = Admin
        fields = ["full_name", "username", "image", "mobile"]
        widgets = {
            "full_name": forms.TextInput(attrs={"class": "form-control"}),
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "image": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "mobile": forms.TextInput(attrs={"class": "form-control"}),
        }

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if User.objects.filter(username=username).exclude(id=self.instance.user.id).exists():
            raise forms.ValidationError("This username is already taken.")
        return username

    def clean_confirm_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        confirm_new_password = self.cleaned_data.get("confirm_new_password")
        if new_password and new_password != confirm_new_password:
            raise forms.ValidationError("New passwords do not match.")
        return confirm_new_password

    def save(self, commit=True):
        admin = super().save(commit=False)
        user = admin.user
        user.username = self.cleaned_data["username"]

        new_password = self.cleaned_data.get("new_password")
        if new_password:
            user.set_password(new_password)

        user.save()
        if commit:
            admin.save()
        return admin


class CustomerProfileUpdateForm(forms.ModelForm):
    new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "autocomplete": "new-password"}),
        required=False,
        label="New Password",
        help_text="Leave blank if you don't want to change it."
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "autocomplete": "new-password"}),
        required=False,
        label="Confirm New Password"
    )

    class Meta:
        model = Customer
        fields = ["full_name", "username", "address", "mobile", "image"]
        widgets = {
            "full_name": forms.TextInput(attrs={"class": "form-control"}),
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "address": forms.TextInput(attrs={"class": "form-control"}),
            "image": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "mobile": forms.TextInput(attrs={"class": "form-control"}),
        }

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if Customer.objects.filter(username=username).exclude(id=self.instance.id).exists():
            raise forms.ValidationError("This username is already taken.")
        return username

    def clean_confirm_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        confirm_new_password = self.cleaned_data.get("confirm_new_password")
        if new_password and new_password != confirm_new_password:
            raise forms.ValidationError("New passwords do not match.")
        return confirm_new_password

    def save(self, commit=True):
        customer = super().save(commit=False)

        new_password = self.cleaned_data.get("new_password")
        if new_password:
            customer.set_password(new_password)

        if commit:
            customer.save()
        return customer


class ProductForm(forms.ModelForm):
    more_images = forms.FileField(
        required=False, widget=forms.FileInput(attrs={"class": "form-control"})
    )

    class Meta:
        model = Product
        fields = [
            "title",
            "category",
            "image",
            "marked_price",
            "selling_price",
            "description",
            "warranty",
            "stock_quantity",
            "return_policy",
        ]
        widgets = {
            "title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Enter the product title here...",
                }
            ),
            "category": forms.Select(attrs={"class": "form-control"}),
            "image": forms.ClearableFileInput(attrs={"class": "form-control"}),
            "marked_price": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Marked price of the product...",
                }
            ),
            "selling_price": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Selling price of the product...",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "placeholder": "Description of the product...",
                    "rows": 5,
                }
            ),
            "warranty": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Enter the product warranty here...",
                }
            ),
            "return_policy": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Enter the product return policy here...",
                }
            ),
            "stock_quantity": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Available stock of the product...",
                }
            ),
        }


class CategoryForm(forms.ModelForm):
    class Meta:
        model = Category
        fields = ["title"]
        widgets = {
            "title": forms.TextInput(
                attrs={"class": "form-control", "placeholder": "Category Title"}
            ),
        }


class PasswordForgotForm(forms.Form):
    email = forms.CharField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter the email used in customer account...",
            }
        )
    )

    def clean_email(self):
        e = self.cleaned_data.get("email")
        if Customer.objects.filter(email=e).exists():
            pass
        else:
            raise forms.ValidationError("Customer with this account does not exists..")
        return e


class PasswordResetForm(forms.Form):
    new_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
                "placeholder": "Enter New Password",
            }
        ),
        label="New Password",
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "autocomplete": "new-password",
                "placeholder": "Confirm New Password",
            }
        ),
        label="Confirm New Password",
    )

    def clean_confirm_new_password(self):
        new_password = self.cleaned_data.get("new_password")
        confirm_new_password = self.cleaned_data.get("confirm_new_password")
        if new_password != confirm_new_password:
            raise forms.ValidationError("New Passwords did not match!")
        return confirm_new_password
