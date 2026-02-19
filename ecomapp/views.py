import requests
from django.views.generic import (
    View,
    TemplateView,
    CreateView,
    FormView,
    DetailView,
    ListView,
    UpdateView,
    DeleteView,
)
from django.db import transaction
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy, reverse
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import JsonResponse
from django.core.mail import send_mail
from django.conf import settings
from django.db.models import Q
from .forms import StockUpdateForm
from .models import *
from .forms import *
from .utils import password_reset_token


def update_stock(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    if request.method == "POST":
        form = StockUpdateForm(request.POST)
        if form.is_valid():
            new_stock_quantity = form.cleaned_data["stock_quantity"]
            product.stock_quantity = new_stock_quantity
            product.save()
            return redirect("product_detail", product_id=product.id)

    else:
        form = StockUpdateForm()

    return render(request, "update_stock.html", {"form": form, "product": product})


class EcomMixin(object):
    def dispatch(self, request, *args, **kwargs):
        cart_id = request.session.get("cart_id")
        customer_id = request.session.get("customer_id")

        if customer_id:
            try:
                customer = Customer.objects.get(id=customer_id)
                request.customer = customer
            except Customer.DoesNotExist:
                # If customer in session doesn't exist, clear session
                request.session.pop("customer_id", None)
                request.session.pop("customer_name", None)
                request.customer = None
        else:
            request.customer = None

        if cart_id:
            try:
                cart_obj = Cart.objects.get(id=cart_id)
                if hasattr(request, "customer") and request.customer:
                    cart_obj.customer = request.customer
                    cart_obj.save()
                request.cart = cart_obj
            except Cart.DoesNotExist:
                del request.session["cart_id"]
                request.cart = None
        else:
            request.cart = None
        return super().dispatch(request, *args, **kwargs)


class HomeView(EcomMixin, TemplateView):
    template_name = "home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["myname"] = "Handicraft"
        all_products = Product.objects.all().order_by("-id")
        paginator = Paginator(all_products, 8)
        page_number = self.request.GET.get("page")
        print(page_number)
        product_list = paginator.get_page(page_number)
        context["product_list"] = product_list
        return context


class AllProductsView(EcomMixin, TemplateView):
    template_name = "allproducts.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["allcategories"] = Category.objects.all()
        return context


class ProductDetailView(EcomMixin, TemplateView):
    template_name = "productdetail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        url_slug = self.kwargs["slug"]
        product = Product.objects.get(slug=url_slug)
        product.view_count += 1
        product.save()
        context["product"] = product
        return context


class AddToCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        # get product id from requested url
        product_id = self.kwargs["pro_id"]
        # get product
        product_obj = get_object_or_404(Product, id=product_id)

        # check if cart exists
        cart_id = request.session.get("cart_id", None)
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            this_product_in_cart = cart_obj.cartproduct_set.filter(product=product_obj)

            # item already exists in cart
            if this_product_in_cart.exists():
                cartproduct = this_product_in_cart.last()
                cartproduct.quantity += 1
                cartproduct.subtotal += product_obj.selling_price
                cartproduct.save()
                cart_obj.total += product_obj.selling_price
                cart_obj.save()
            # new item is added in cart
            else:
                cartproduct = CartProduct.objects.create(
                    cart=cart_obj,
                    product=product_obj,
                    rate=product_obj.selling_price,
                    quantity=1,
                    subtotal=product_obj.selling_price,
                )
                cart_obj.total += product_obj.selling_price
                cart_obj.save()

        else:
            cart_obj = Cart.objects.create(total=0)
            request.session["cart_id"] = cart_obj.id
            cartproduct = CartProduct.objects.create(
                cart=cart_obj,
                product=product_obj,
                rate=product_obj.selling_price,
                quantity=1,
                subtotal=product_obj.selling_price,
            )
            cart_obj.total += product_obj.selling_price
            cart_obj.save()

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "status": "success",
                    "message": "Item added to cart successfully",
                    "cart_total": cart_obj.total,
                    "cart_count": cart_obj.cartproduct_set.count(),
                }
            )

        messages.success(request, "Item added to cart")
        return redirect(request.META.get("HTTP_REFERER", reverse("ecomapp:home")))


class ManageCartView(EcomMixin, View):
    def get(self, request, *args, **kwargs):
        cp_id = self.kwargs["cp_id"]
        action = request.GET.get("action")
        cp_obj = CartProduct.objects.get(id=cp_id)
        cart_obj = cp_obj.cart

        item_removed = False

        if action == "inc":
            cp_obj.quantity += 1
            cp_obj.subtotal += cp_obj.rate
            cp_obj.save()
            cart_obj.total += cp_obj.rate
            cart_obj.save()
        elif action == "dcr":
            if cp_obj.quantity > 1:
                cp_obj.quantity -= 1
                cp_obj.subtotal -= cp_obj.rate
                cp_obj.save()
                cart_obj.total -= cp_obj.rate
                cart_obj.save()
            else:
                cart_obj.total -= cp_obj.subtotal
                cart_obj.save()
                cp_obj.delete()
                item_removed = True
        elif action == "rmv":
            cart_obj.total -= cp_obj.subtotal
            cart_obj.save()
            cp_obj.delete()
            item_removed = True
        else:
            pass

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "status": "success",
                    "message": "Cart updated",
                    "cart_total": cart_obj.total,
                    "cart_count": cart_obj.cartproduct_set.count(),
                    "item_qty": 0 if item_removed else cp_obj.quantity,
                    "item_subtotal": 0 if item_removed else cp_obj.subtotal,
                    "action": action,
                }
            )

        return redirect("ecomapp:mycart")


class EmptyCartView(EcomMixin, View):
    def get(self, request):
        cart_id = request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
            cart.cartproduct_set.all().delete()
            cart.total = 0
            cart.save()
        return redirect("ecomapp:mycart")


class MyCartView(EcomMixin, TemplateView):
    template_name = "mycart.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart = Cart.objects.get(id=cart_id)
        else:
            cart = None
        context["cart"] = cart
        return context


class CheckoutView(EcomMixin, CreateView):
    template_name = "checkout.html"
    form_class = CheckoutForm
    success_message = "Order Placed Successfully"
    success_url = reverse_lazy("ecomapp:home")

    def dispatch(self, request, *args, **kwargs):
        if request.session.get("customer_id"):
            pass
        else:
            return redirect("/login/?next=/checkout/")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        cart_id = self.request.session.get("cart_id", None)
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
        else:
            cart_obj = None
        context["cart"] = cart_obj
        return context

    def get_initial(self):
        initial = super().get_initial()
        customer_id = self.request.session.get("customer_id")
        if customer_id:
            customer = Customer.objects.get(id=customer_id)
            initial["ordered_by"] = customer.full_name
            initial["shipping_address"] = customer.address
            initial["email"] = customer.email
        return initial

    def form_valid(self, form):
        cart_id = self.request.session.get("cart_id")
        if cart_id:
            cart_obj = Cart.objects.get(id=cart_id)
            form.instance.cart = cart_obj
            form.instance.subtotal = cart_obj.total
            form.instance.discount = 0
            form.instance.total = cart_obj.total
            form.instance.order_status = "Order Received"
            pm = form.cleaned_data.get("payment_method")

            with transaction.atomic():
                # Lock products to prevent race conditions on stock
                products_in_cart = [cp.product for cp in cart_obj.cartproduct_set.all()]
                Product.objects.select_for_update().filter(
                    id__in=[p.id for p in products_in_cart]
                )

                # Check stock again before creating order
                for cart_product in cart_obj.cartproduct_set.all():
                    product = cart_product.product
                    if product.stock_quantity < cart_product.quantity:
                        messages.error(
                            self.request,
                            f"Not enough stock for {product.title}. Only {product.stock_quantity} left.",
                        )
                        return redirect("ecomapp:mycart")

                order = form.save()

                # Deduct stock
                for cart_product in cart_obj.cartproduct_set.all():
                    product = cart_product.product
                    product.stock_quantity -= cart_product.quantity
                    product.save()

            del self.request.session["cart_id"]

            if pm == "Khalti":
                return redirect(
                    reverse("ecomapp:khaltirequest") + "?o_id=" + str(order.id)
                )
            elif pm == "Esewa":
                return redirect(
                    reverse("ecomapp:esewarequest") + "?o_id=" + str(order.id)
                )
        else:
            return redirect("ecomapp:home")
        return super().form_valid(form)


class KhaltiRequestView(View):
    def get(self, request, *args, **kwargs):
        o_id = request.GET.get("o_id")
        order = Order.objects.get(id=o_id)
        context = {"order": order}
        return render(request, "khaltirequest.html", context)


class KhaltiVerifyView(View):
    def get(self, request, *args, **kwargs):
        token = request.GET.get("token")
        amount = request.GET.get("amount")
        o_id = request.GET.get("order_id")
        print(token, amount, o_id)

        url = "https://khalti.com/api/v2/payment/verify/"
        payload = {"token": token, "amount": amount}
        headers = {
            "Authorization": "Key test_secret_key_f59e8b7d18b4499ca40f68195a846e9b"
        }

        order_obj = Order.objects.get(id=o_id)

        response = requests.post(url, data=payload, headers=headers)
        resp_dict = response.json()
        if resp_dict.get("idx"):
            success = True
            order_obj.payment_completed = True
            order_obj.save()
        else:
            success = False
        data = {"success": success}
        return JsonResponse(data)


class EsewaRequestView(View):
    def get(self, request, *args, **kwargs):
        o_id = request.GET.get("o_id")
        order = Order.objects.get(id=o_id)
        context = {"order": order}
        return render(request, "esewarequest.html", context)


class EsewaVerifyView(View):
    def get(self, request, *args, **kwargs):
        import xml.etree.ElementTree as ET

        oid = request.GET.get("oid")
        amt = request.GET.get("amt")
        refId = request.GET.get("refId")

        url = "https://uat.esewa.com.np/epay/transrec"
        d = {
            "amt": amt,
            "scd": "epay_payment",
            "rid": refId,
            "pid": oid,
        }
        resp = requests.post(url, d)
        root = ET.fromstring(resp.content)
        status = root[0].text.strip()

        order_id = oid.split("_")[1]
        order_obj = Order.objects.get(id=order_id)
        if status == "Success":
            order_obj.payment_completed = True
            order_obj.save()
            return redirect("/")
        else:
            return redirect("/esewa-request/?o_id=" + order_id)


class CustomerRegistrationView(EcomMixin, CreateView):
    template_name = "customerregistration.html"
    form_class = CustomerRegistrationForm
    success_url = reverse_lazy("ecomapp:home")

    def form_valid(self, form):
        customer = form.save()
        # Manual session login
        self.request.session['customer_id'] = customer.id
        self.request.session['customer_name'] = customer.full_name

        return redirect(self.get_success_url())

    def get_success_url(self):
        return self.request.GET.get("next", self.success_url)


class CustomerLogoutView(View):
    def get(self, request):
        request.session.pop('customer_id', None)
        request.session.pop('customer_name', None)
        return redirect("ecomapp:home")


class CustomerLoginView(EcomMixin, FormView):
    template_name = "customerlogin.html"
    form_class = CustomerLoginForm
    success_url = reverse_lazy("ecomapp:home")

    def form_valid(self, form):
        uname = form.cleaned_data.get("username")
        pword = form.cleaned_data.get("password")

        try:
            customer = Customer.objects.get(username=uname)
        except Customer.DoesNotExist:
            return render(
                self.request,
                self.template_name,
                {"form": self.form_class, "error": "Invalid credentials"},
            )

        if customer.check_password(pword):
            # Store customer info in session
            self.request.session['customer_id'] = customer.id
            self.request.session['customer_name'] = customer.full_name
            return redirect(self.get_success_url())
        else:
            return render(
                self.request,
                self.template_name,
                {"form": self.form_class, "error": "Invalid credentials"},
            )

    def get_success_url(self):
        return self.request.GET.get("next", self.success_url)


class AboutView(EcomMixin, TemplateView):
    template_name = "about.html"


class ContactView(EcomMixin, TemplateView):
    template_name = "contactus.html"


class CustomerProfileView(EcomMixin, TemplateView):
    template_name = "customerprofile.html"
    def dispatch(self, request, *args, **kwargs):
        if not request.session.get("customer_id"):
            return redirect("/login/?next=/profile/")
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        customer_id = self.request.session.get("customer_id")
        customer = get_object_or_404(Customer, id=customer_id)
        context["customer"] = customer
        orders = Order.objects.filter(cart__customer=customer).order_by("-id")
        context["orders"] = orders
        return context
    

class CustomerProfileEditView(EcomMixin, UpdateView):
    template_name = "customerprofileedit.html"
    form_class = CustomerProfileUpdateForm
    success_url = reverse_lazy("ecomapp:customerprofile")

    def dispatch(self, request, *args, **kwargs):
        if not request.session.get("customer_id"):
            return redirect("/login/?next=/profile/edit/")
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        customer_id = self.request.session.get("customer_id")
        return get_object_or_404(Customer, id=customer_id)

    def form_valid(self, form):
        messages.success(self.request, "Profile updated successfully!")
        return super().form_valid(form)


class CustomerAccountDeleteView(EcomMixin, TemplateView):
    template_name = "customeraccount_delete.html"

    def dispatch(self, request, *args, **kwargs):
        if not request.session.get("customer_id"):
            return redirect("/login/?next=/profile/delete/")
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        customer_id = request.session.get("customer_id")
        if customer_id:
            customer = get_object_or_404(Customer, id=customer_id)
            customer.delete()
            request.session.pop("customer_id", None)
            request.session.pop("customer_name", None)
        messages.success(request, "Your account has been permanently deleted.")
        return redirect("ecomapp:home")

class CustomerOrderDetailView(EcomMixin, DetailView):
    template_name = "customerorderdetail.html"
    model = Order
    context_object_name = "ord_obj"

    def dispatch(self, request, *args, **kwargs):
        customer_id = request.session.get("customer_id")
        if customer_id:
            order_id = self.kwargs["pk"]
            order = Order.objects.get(id=order_id)
            if order.cart.customer_id != customer_id:
                return redirect("ecomapp:myprofile")
        else:
            return redirect(f"/login/?next={request.path}")
        return super().dispatch(request, *args, **kwargs)


class SearchView(EcomMixin, TemplateView):
    template_name = "search.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        kw = self.request.GET.get("keyword")
        results = Product.objects.filter(
            Q(title__icontains=kw)
            | Q(description__icontains=kw)
            | Q(return_policy__icontains=kw)
        )
        print(results)
        context["results"] = results
        return context


class PasswordForgotView(EcomMixin, FormView):
    template_name = "forgotpassword.html"
    form_class = PasswordForgotForm
    success_url = "/forgot-password/?m=s"

    def form_valid(self, form):
        # get email from user
        email = form.cleaned_data.get("email")
        # get current host ip/domain
        url = self.request.META["HTTP_HOST"]
        # get customer
        customer = Customer.objects.get(email=email)
        # send mail to the user with email
        text_content = "Please Click the link below to reset your password. "
        html_content = (
            url
            + "/password-reset/"
            + email
            + "/"
            + password_reset_token.make_token(customer)
            + "/"
        )
        send_mail(
            "Password Reset Link | Django Ecommerce",
            text_content + html_content,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        return super().form_valid(form)


class PasswordResetView(EcomMixin, FormView):
    template_name = "passwordreset.html"
    form_class = PasswordResetForm
    success_url = "/login/"

    def dispatch(self, request, *args, **kwargs):
        email = self.kwargs.get("email")
        customer = get_object_or_404(Customer, email=email)
        token = self.kwargs.get("token")
        if customer is not None and password_reset_token.check_token(customer, token):
            pass
        else:
            return redirect(reverse("ecomapp:passworforgot") + "?m=e")

        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        password = form.cleaned_data["new_password"]
        email = self.kwargs.get("email")
        customer = Customer.objects.get(email=email)
        customer.set_password(password)
        customer.save()
        return super().form_valid(form)


# admin pages


class AdminLoginView(FormView):
    template_name = "adminpages/adminlogin.html"
    form_class = CustomerLoginForm
    success_url = reverse_lazy("ecomapp:adminhome")

    def form_valid(self, form):
        uname = form.cleaned_data.get("username")
        pword = form.cleaned_data["password"]
        usr = authenticate(username=uname, password=pword)
        if usr is not None and Admin.objects.filter(user=usr).exists():
            login(self.request, usr)
        else:
            return render(
                self.request,
                self.template_name,
                {"form": self.form_class, "error": "Invalid credentials"},
            )
        return super().form_valid(form)


class AdminRegistrationView(CreateView):
    template_name = "adminpages/adminregister.html"
    form_class = AdminRegistrationForm
    success_url = reverse_lazy("ecomapp:adminhome")

    def form_valid(self, form):
        admin = form.save()
        login(self.request, admin.user)
        return redirect(self.success_url)


class AdminLogoutView(View):
    def get(self, request):
        logout(request)
        return redirect("ecomapp:adminhome")


class AdminRequiredMixin(object):
    def dispatch(self, request, *args, **kwargs):
        if (
            request.user.is_authenticated
            and Admin.objects.filter(user=request.user).exists()
        ):
            pass
        else:
            return redirect("/admin-login/")
        return super().dispatch(request, *args, **kwargs)


class AdminProfileEditView(AdminRequiredMixin, UpdateView):
    template_name = "adminpages/adminprofileedit.html"
    form_class = AdminProfileUpdateForm
    success_url = reverse_lazy("ecomapp:adminprofile")

    def get_object(self, queryset=None):
        return self.request.user.admin

    def form_valid(self, form):
        messages.success(self.request, "Admin Profile updated successfully!")
        return super().form_valid(form)


class AdminAccountDeleteView(AdminRequiredMixin, TemplateView):
    template_name = "adminpages/adminaccount_delete.html"

    def post(self, request, *args, **kwargs):
        user = request.user
        logout(request)
        user.delete()
        messages.success(request, "Your account has been permanently deleted.")
        return redirect("ecomapp:home")

class AdminHomeView(AdminRequiredMixin, TemplateView):
    template_name = "adminpages/adminhome.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["pendingorders"] = Order.objects.filter(order_status="Order Received").order_by("-id")
        context["total_orders"] = Order.objects.count()
        context["total_products"] = Product.objects.count()
        context["total_customers"] = Customer.objects.count()
        context["total_categories"] = Category.objects.count()
        return context


class AdminProfileView(AdminRequiredMixin, TemplateView):
    template_name = "adminpages/adminprofile.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["admin"] = self.request.user.admin
        
        return context


class AdminOrderDetailView(AdminRequiredMixin, DetailView):
    template_name = "adminpages/adminorderdetail.html"
    model = Order
    context_object_name = "ord_obj"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["allstatus"] = ORDER_STATUS
        return context


class AdminOrderListView(AdminRequiredMixin, ListView):
    template_name = "adminpages/adminorderlist.html"
    queryset = Order.objects.all().order_by("-id")
    context_object_name = "allorders"


class AdminOrderStatuChangeView(AdminRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        order_id = self.kwargs["pk"]
        order_obj = Order.objects.get(id=order_id)
        new_status = request.POST.get("status")
        order_obj.order_status = new_status
        order_obj.save()
        return redirect(
            reverse_lazy("ecomapp:adminorderdetail", kwargs={"pk": order_id})
        )


class AdminProductListView(AdminRequiredMixin, ListView):
    template_name = "adminpages/adminproductlist.html"
    queryset = Product.objects.all().order_by("-id")
    context_object_name = "allproducts"


class AdminCategoryListView(AdminRequiredMixin, ListView):
    template_name = "adminpages/admincategorylist.html"
    queryset = Category.objects.all().order_by("-id")
    context_object_name = "allcategories"


class AdminProductCreateView(AdminRequiredMixin, CreateView):
    template_name = "adminpages/adminproductcreate.html"
    form_class = ProductForm
    success_url = reverse_lazy("ecomapp:adminproductlist")

    def form_valid(self, form):
        p = form.save()
        images = self.request.FILES.getlist("more_images")
        for i in images:
            ProductImage.objects.create(product=p, image=i)
        return super().form_valid(form)


class AdminCategoryCreateView(AdminRequiredMixin, CreateView):
    template_name = "adminpages/admincategorycreate.html"
    form_class = CategoryForm
    success_url = reverse_lazy("ecomapp:admincategorylist")


class AdminProductUpdateView(AdminRequiredMixin, UpdateView):
    template_name = "adminpages/adminproductupdate.html"
    form_class = ProductForm
    success_url = reverse_lazy("ecomapp:adminproductlist")
    model = Product

    def form_valid(self, form):
        p = form.save()
        images = self.request.FILES.getlist("more_images")
        for i in images:
            ProductImage.objects.create(product=p, image=i)
        return super().form_valid(form)


class AdminProductDeleteView(AdminRequiredMixin, DeleteView):
    template_name = "adminpages/adminproductdelete.html"
    success_url = reverse_lazy("ecomapp:adminproductlist")
    model = Product


class AdminCategoryUpdateView(AdminRequiredMixin, UpdateView):
    template_name = "adminpages/admincategoryupdate.html"
    form_class = CategoryForm
    success_url = reverse_lazy("ecomapp:admincategorylist")
    model = Category


class AdminCategoryDeleteView(AdminRequiredMixin, DeleteView):
    template_name = "adminpages/admincategorydelete.html"
    success_url = reverse_lazy("ecomapp:admincategorylist")
    model = Category
