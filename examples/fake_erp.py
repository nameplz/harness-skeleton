"""A tiny in-memory ERP fixture for exercising project CI."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Product:
    sku: str
    name: str
    unit_price_cents: int
    quantity: int


@dataclass(frozen=True)
class Order:
    number: int
    lines: tuple[tuple[str, int], ...]
    total_cents: int


class FakeERP:
    def __init__(self, products: Iterable[Product]) -> None:
        self._products: dict[str, Product] = {}
        self._stock: dict[str, int] = {}
        for product in products:
            if (
                not product.sku
                or product.sku in self._products
                or not product.name
                or type(product.unit_price_cents) is not int
                or product.unit_price_cents < 0
                or type(product.quantity) is not int
                or product.quantity < 0
            ):
                raise ValueError("invalid or duplicate product")
            self._products[product.sku] = product
            self._stock[product.sku] = product.quantity
        self._next_order_number = 1

    def inventory(self, sku: str) -> int:
        try:
            return self._stock[sku]
        except KeyError as exc:
            raise ValueError(f"unknown SKU: {sku}") from exc

    def place_order(self, items: Mapping[str, int]) -> Order:
        if not items:
            raise ValueError("an order must contain at least one item")

        lines = tuple(items.items())
        for sku, quantity in lines:
            if sku not in self._products:
                raise ValueError(f"unknown SKU: {sku}")
            if type(quantity) is not int or quantity < 1:
                raise ValueError("order quantities must be positive integers")
            if quantity > self._stock[sku]:
                raise ValueError(f"insufficient stock for SKU: {sku}")

        order = Order(
            number=self._next_order_number,
            lines=lines,
            total_cents=sum(self._products[sku].unit_price_cents * quantity for sku, quantity in lines),
        )
        for sku, quantity in lines:
            self._stock[sku] -= quantity
        self._next_order_number += 1
        return order
