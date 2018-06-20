package cli

import (

	messages "github.com/skycoin/skycoin/protob"
	deviceWallet "github.com/skycoin/skycoin/src/device-wallet"
	gcli "github.com/urfave/cli"
)

func emulatorAddressGenCmd() gcli.Command {
	name := "emulatorAddressGen"
	return gcli.Command{
		Name:        name,
		Usage:       "Generate skycoin or bitcoin addresses using an emulated device.",
		Description: "",
		Flags: []gcli.Flag{
			gcli.IntFlag{
				Name:  "addressN",
				Value: 1,
				Usage: "Index for deterministic key generation. Assume 1 if not set.",
			},
			gcli.BoolFlag{
				Name:  "bitcoin,b",
				Usage: "Output the addresses as bitcoin addresses instead of skycoin addresses",
			},
		},
		OnUsageError: onCommandUsageError(name),
		Action: func(c *gcli.Context) {
			var coinType messages.SkycoinAddressType
			if c.Bool("bitcoin") {
				coinType = messages.SkycoinAddressType_AddressTypeBitcoin
			} else {
				coinType = messages.SkycoinAddressType_AddressTypeSkycoin
			}

			addressN := c.Int("addressN")
			deviceWallet.DeviceAddressGen(deviceWallet.DeviceTypeEmulator, coinType, addressN)
		},
	}
}