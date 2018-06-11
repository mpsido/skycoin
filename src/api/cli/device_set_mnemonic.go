package cli

import (
	hardwareWallet "github.com/skycoin/skycoin/src/hardware-wallet"
	gcli "github.com/urfave/cli"
)

func deviceSetMnemonicCmd() gcli.Command {
	name := "deviceSetMnemonic"
	return gcli.Command{
		Name:        name,
		Usage:       "Configure the device with a mnemonic.",
		Description: "",
		Flags: []gcli.Flag{
			gcli.StringFlag{
				Name:  "mnemonic",
				Usage: "Mnemonic that will be stored in the device to generate addresses.",
			},
		},
		OnUsageError: onCommandUsageError(name),
		Action: func(c *gcli.Context) {
			mnemonic := c.String("mnemonic")
			hardwareWallet.DeviceSetMnemonic(mnemonic)
		},
	}
}
