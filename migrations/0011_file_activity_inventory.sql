ALTER TABLE runtime_inventory_items
    DROP CONSTRAINT runtime_inventory_items_inventory_kind_check,
    ADD CONSTRAINT runtime_inventory_items_inventory_kind_check
        CHECK (
            inventory_kind IN (
                'process', 'destination', 'domain', 'syscall',
                'inbound_endpoint', 'file_activity'
            )
        );
