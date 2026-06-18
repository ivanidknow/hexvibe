// Vulnerable: NST-030
@Controller()
export class AppController2 {
  constructor(private readonly appService: AppService) {}
  @Get()
  @Header('access-control-allow-origin', '*')
  testCtrl2(): string {
    return this.appService.getHello();
  }
}
