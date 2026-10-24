from __future__ import annotations

import unittest

from examples.fake_erp import FakeERP, Product


class FakeERPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.products = (
            Product("BOLT-1", "Bolt", 125, 5),
            Product("WIDGET-1", "Widget", 400, 1),
        )
        self.erp = FakeERP(self.products)

    def test_order_prices_items_and_reduces_inventory(self) -> None:
        order = self.erp.place_order({"BOLT-1": 2, "WIDGET-1": 1})

        self.assertEqual((1, (("BOLT-1", 2), ("WIDGET-1", 1)), 650),
                         (order.number, order.lines, order.total_cents))
        self.assertEqual(3, self.erp.inventory("BOLT-1"))
        self.assertEqual(0, self.erp.inventory("WIDGET-1"))

    def test_invalid_orders_leave_all_inventory_unchanged(self) -> None:
        invalid_orders = (
            {},
            {"BOLT-1": 0},
            {"MISSING": 1},
            {"BOLT-1": 6},
            {"BOLT-1": 1, "WIDGET-1": 2},
        )
        for items in invalid_orders:
            with self.subTest(items=items):
                erp = FakeERP(self.products)
                with self.assertRaises(ValueError):
                    erp.place_order(items)
                self.assertEqual(5, erp.inventory("BOLT-1"))
                self.assertEqual(1, erp.inventory("WIDGET-1"))


if __name__ == "__main__":
    unittest.main()
