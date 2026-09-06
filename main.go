package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	_ "unsafe"
	"x-ui/config"
	"x-ui/database"
	"x-ui/logger"
	passwordutil "x-ui/util/password"
	"x-ui/v2ui"
	"x-ui/web"
	"x-ui/web/global"
	"x-ui/web/service"
	"x-ui/xray"

	"github.com/op/go-logging"
)

func runWebServer() {
	log.Printf("%v %v", config.GetName(), config.GetVersion())

	switch config.GetLogLevel() {
	case config.Debug:
		logger.InitLogger(logging.DEBUG)
	case config.Info:
		logger.InitLogger(logging.INFO)
	case config.Warn:
		logger.InitLogger(logging.WARNING)
	case config.Error:
		logger.InitLogger(logging.ERROR)
	default:
		log.Fatal("unknown log level:", config.GetLogLevel())
	}

	err := database.InitDB(config.GetDBPath())
	if err != nil {
		log.Fatal(err)
	}
	userService := service.UserService{}
	if err := userService.MigratePasswordHashes(); err != nil {
		log.Fatal(err)
	}
	username, initialPassword, created, err := userService.EnsureInitialUser()
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("initial administrator created; username=%s password=%s (change it immediately)", username, initialPassword)
	}

	var server *web.Server

	server = web.NewServer()
	global.SetWebServer(server)
	err = server.Start()
	if err != nil {
		log.Println(err)
		return
	}

	sigCh := make(chan os.Signal, 1)
	//信号量捕获处理
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)
	for {
		sig := <-sigCh

		switch sig {
		case syscall.SIGHUP:
			err := server.Stop()
			if err != nil {
				logger.Warning("stop server err:", err)
			}
			server = web.NewServer()
			global.SetWebServer(server)
			err = server.Start()
			if err != nil {
				log.Println(err)
				return
			}
		default:
			if err := server.Stop(); err != nil {
				logger.Warning("stop server err:", err)
			}
			return
		}
	}
}

func resetSetting() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}
	err = settingService.ResetSettings()
	if err != nil {
		fmt.Println("reset setting failed:", err)
	} else {
		fmt.Println("reset setting success")
	}
}

func showSetting(show bool) {
	if show {
		settingService := service.SettingService{}
		port, err := settingService.GetPort()
		if err != nil {
			fmt.Println("get current port fialed,error info:", err)
		}
		userService := service.UserService{}
		userModel, err := userService.GetFirstUser()
		if err != nil {
			fmt.Println("get current user info failed,error info:", err)
			return
		}
		fmt.Println("current pannel settings as follows:")
		fmt.Println("username:", userModel.Username)
		fmt.Println("password: [hidden]")
		fmt.Println("port:", port)
	}
}

func updateTgbotEnableSts(status bool) {
	settingService := service.SettingService{}
	currentTgSts, err := settingService.GetTgbotenabled()
	if err != nil {
		fmt.Println(err)
		return
	}
	logger.Infof("current enabletgbot status[%v],need update to status[%v]", currentTgSts, status)
	if currentTgSts != status {
		err := settingService.SetTgbotenabled(status)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("SetTgbotenabled[%v] success", status)
		}
	}
	return
}

func updateTgbotSetting(tgBotToken string, tgBotChatid int, tgBotRuntime string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	settingService := service.SettingService{}

	if tgBotToken != "" {
		err := settingService.SetTgBotToken(tgBotToken)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotToken success")
		}
	}

	if tgBotRuntime != "" {
		err := settingService.SetTgbotRuntime(tgBotRuntime)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Infof("updateTgbotSetting tgBotRuntime[%s] success", tgBotRuntime)
		}
	}

	if tgBotChatid != 0 {
		err := settingService.SetTgBotChatId(tgBotChatid)
		if err != nil {
			fmt.Println(err)
			return
		} else {
			logger.Info("updateTgbotSetting tgBotChatid success")
		}
	}
}

func updateSetting(port int, username string, password string) error {
	// Reject invalid credentials before creating a database or changing a port.
	if username != "" || password != "" {
		if err := passwordutil.ValidateUsername(username); err != nil {
			return err
		}
		if err := passwordutil.ValidatePassword(password); err != nil {
			return err
		}
	}
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		return err
	}

	settingService := service.SettingService{}

	if port > 0 {
		err := settingService.SetPort(port)
		if err != nil {
			return fmt.Errorf("set port failed: %w", err)
		}
		fmt.Printf("set port %v success\n", port)
	}
	if username != "" || password != "" {
		userService := service.UserService{}
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			return fmt.Errorf("set username and password failed: %w", err)
		}
		fmt.Println("set username and password success")
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		runWebServer()
		return
	}

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")

	runCmd := flag.NewFlagSet("run", flag.ExitOnError)

	v2uiCmd := flag.NewFlagSet("v2-ui", flag.ExitOnError)
	var dbPath string
	v2uiCmd.StringVar(&dbPath, "db", "/etc/v2-ui/v2-ui.db", "set v2-ui db file path")

	settingCmd := flag.NewFlagSet("setting", flag.ExitOnError)
	var port int
	var username string
	var password string
	var passwordStdin bool
	var validatePassword bool
	var tgbottoken string
	var tgbotchatid int
	var enabletgbot bool
	var tgbotRuntime string
	var reset bool
	var show bool
	settingCmd.BoolVar(&reset, "reset", false, "reset all settings")
	settingCmd.BoolVar(&show, "show", false, "show current settings")
	settingCmd.IntVar(&port, "port", 0, "set panel port")
	settingCmd.StringVar(&username, "username", "", "set login username")
	settingCmd.BoolVar(&passwordStdin, "password-stdin", false, "read login password from stdin")
	settingCmd.BoolVar(&validatePassword, "validate-password", false, "validate stdin password without changing settings (at least 8 characters, at most 72 UTF-8 bytes)")
	settingCmd.StringVar(&tgbottoken, "tgbottoken", "", "set telegrame bot token")
	settingCmd.StringVar(&tgbotRuntime, "tgbotRuntime", "", "set telegrame bot cron time")
	settingCmd.IntVar(&tgbotchatid, "tgbotchatid", 0, "set telegrame bot chat id")
	settingCmd.BoolVar(&enabletgbot, "enabletgbot", false, "enable telegram bot notify")

	oldUsage := flag.Usage
	flag.Usage = func() {
		oldUsage()
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("    run            run web panel")
		fmt.Println("    v2-ui          migrate form v2-ui")
		fmt.Println("    setting        set settings")
		fmt.Println("    tun enable     check TUN availability (root service needs no separate authorization)")
		fmt.Println("    tun disable    show how to disable TUN inbounds in the panel")
	}

	flag.Parse()
	if showVersion {
		fmt.Println(config.GetVersion())
		return
	}

	switch os.Args[1] {
	case "tun":
		if len(os.Args) != 3 || (os.Args[2] != "enable" && os.Args[2] != "disable") {
			fmt.Fprintln(os.Stderr, "用法：x-ui tun enable|disable；新版默认 root 运行，不再设置单独的 TUN 授权")
			os.Exit(2)
		}
		if os.Args[2] == "enable" {
			if err := xray.CheckTUNSupport(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("当前进程具备 TUN 权限。新版服务默认 root 运行，无需单独授权；请在面板创建或启用 TUN 入站。此命令不修改服务配置、不重启面板。")
		} else {
			fmt.Println("请在面板停用或删除 TUN 入站。新版默认 root 运行，不再设置单独的 TUN 授权开关；此命令未修改配置，也未停止入站。")
		}
	case "run":
		err := runCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		runWebServer()
	case "v2-ui":
		err := v2uiCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Println(err)
			return
		}
		// Offline migration now validates with the installed core. Resolve the
		// input before changing directory so a relative -db keeps its meaning.
		dbPath, err = filepath.Abs(dbPath)
		if err != nil {
			fmt.Println(err)
			return
		}
		executable, err := os.Executable()
		if err != nil {
			fmt.Println(err)
			return
		}
		executable, err = filepath.EvalSymlinks(executable)
		if err != nil {
			fmt.Println(err)
			return
		}
		if err := os.Chdir(filepath.Dir(executable)); err != nil {
			fmt.Println(err)
			return
		}
		err = v2ui.MigrateFromV2UI(dbPath)
		if err != nil {
			fmt.Println("migrate from v2-ui failed:", err)
		}
	case "setting":
		err := settingCmd.Parse(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if validatePassword && !passwordStdin {
			fmt.Fprintln(os.Stderr, "校验密码需要通过 -password-stdin 输入密码")
			os.Exit(1)
		}
		if passwordStdin {
			value, readErr := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if readErr != nil {
				fmt.Fprintln(os.Stderr, "read password failed:", readErr)
				os.Exit(1)
			}
			password = strings.TrimRight(string(value), "\r\n")
			if err := passwordutil.ValidatePassword(password); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if validatePassword {
			return
		}
		if reset {
			resetSetting()
		} else {
			if err := updateSetting(port, username, password); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if show {
			showSetting(show)
		}
		if (tgbottoken != "") || (tgbotchatid != 0) || (tgbotRuntime != "") {
			updateTgbotSetting(tgbottoken, tgbotchatid, tgbotRuntime)
		}
	default:
		fmt.Println("except 'run' or 'v2-ui' or 'setting' subcommands")
		fmt.Println()
		runCmd.Usage()
		fmt.Println()
		v2uiCmd.Usage()
		fmt.Println()
		settingCmd.Usage()
	}
}
