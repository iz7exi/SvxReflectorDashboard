class AddDmrRxTxFreqToBridges < ActiveRecord::Migration[8.1]
  def change
    add_column :bridges, :dmr_rx_freq, :string
    add_column :bridges, :dmr_tx_freq, :string
  end
end
