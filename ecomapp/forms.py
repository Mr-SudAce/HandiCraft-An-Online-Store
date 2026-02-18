from django import forms
from .models import Order, Customer, Product, Admin, Category
from django.contrib.auth.models import User


class StockUpdateForm(forms.Form):
    stock_quantity = forms.IntegerField(label="Stock Quantity")


class CheckoutForm(forms.ModelForm):
    class Meta:
        model = Order
        fields = ["ordered_by", "shipping_address", "mobile", "email", "payment_method"]


class CustomerRegistrationForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput())
    password = forms.CharField(
        min_length=8, max_length=20, widget=forms.PasswordInput()
    )
    email = forms.CharField(widget=forms.EmailInput())

    class Meta:
        model = Customer
        fields = ["username", "password", "email", "full_name", "address"]

    def clean_username(self):
        uname = self.cleaned_data.get("username")

        if User.objects.filter(username=uname).exists():
            raise forms.ValidationError("Customer with this username already exists.")
        return uname


class CustomerLoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput())
    password = forms.CharField(widget=forms.PasswordInput())

class AdminRegistrationForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput())
    password = forms.CharField(widget=forms.PasswordInput())
    email = forms.CharField(widget=forms.EmailInput())

    class Meta:
        model = Admin
        fields = ["username", "password", "email", "full_name", "image", "mobile"]

    def clean_username(self):
        uname = self.cleaned_data.get("username")
        if User.objects.filter(username=uname).exists():
            raise forms.ValidationError("Username already exists.")
        return uname

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already exists.")
        return email


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
        if Customer.objects.filter(user__email=e).exists():
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
