import type {
  LicenseConfig,
  NavBarConfig,
  ProfileConfig,
  SiteConfig,
} from './types/config'
import { LinkPreset } from './types/config'

export const siteConfig: SiteConfig = {
  title: 'lizardqueen',
  subtitle: 'CTF writeups and other notes',
  lang: 'en',
  themeHue: 250,
  banner: {
    enable: false,
    src: 'assets/images/demo-banner.png',
  },
}

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,
    LinkPreset.Archive,
    LinkPreset.About,
    {
      name: 'GitHub',
      url: 'https://github.com/MarianaRioCosta/',
      external: true,
    },
    {
      name: 'LinkedIn',
      url: 'https://www.linkedin.com/in/mariana-rio-costa-90a47921a/',
      external: true,
    },
  ],
}


export const profileConfig: ProfileConfig = {
  avatar: 'assets/images/avatar.jpg',
  name: 'lizardqueen',
  bio: '((:',
  links: [
    {
      name: 'GitHub',
      icon: 'fa6-brands:github',
      url: 'https://github.com/MarianaRioCosta/',
    },
    {
      name: 'LinkedIn',
      icon: 'fa6-brands:linkedin',
      url: 'https://www.linkedin.com/in/mariana-rio-costa-90a47921a/',
    },
  ],
}

export const licenseConfig: LicenseConfig = {
  enable: true,
  name: 'CC BY-NC-SA 4.0',
  url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/',
}
